import { beforeAll, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  activeResourceLease,
  ResourceLeaseFencedError,
  type ResourceLeaseRepository,
} from "../src/identity-sync/resource-lease.ts";
import { GoogleOrgChartDriveClient } from "../src/org-sync/google-org-chart-drive-client.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

const FILE_ID = "app-created-file-id";
const DRIVE_ID = "all-team-drive-id";
const EMPTY_HTML_SHA256 =
  "b633a587c652d02386c4f16f8c6f6aab7352d97f16367c3c40576214372dd628";
const metadata = {
  driveId: DRIVE_ID,
  id: FILE_ID,
  mimeType: "text/html",
  name: "Organization Chart",
  parents: [DRIVE_ID],
  trashed: false,
  webViewLink: `https://drive.google.com/file/d/${FILE_ID}/view`,
};
const DRIVE_V2_FILE_ETAG = { etag: '"etag-v1"', id: FILE_ID };
const SERVICE_ACCOUNT_WRITER_PERMISSION = {
  emailAddress: "org-sync@example.iam.gserviceaccount.com",
  id: "service-account",
  role: "writer",
  type: "user",
};

let testPrivateKey: string;
beforeAll(async () => {
  testPrivateKey = await rsaPrivateKeyFixture();
});

function leaseRepository() {
  return {
    acquire: vi.fn<ResourceLeaseRepository["acquire"]>(
      async (resourceKey, durationMs) => ({
        kind: "acquired",
        lease: activeResourceLease({
          resourceKey,
          generation: 1,
          ownerId: crypto.randomUUID(),
          expiresAtMs: Date.now() + durationMs,
        }),
      }),
    ),
    assertActive: vi.fn<ResourceLeaseRepository["assertActive"]>(
      async () => undefined,
    ),
    release: vi.fn<ResourceLeaseRepository["release"]>(async () => undefined),
  } satisfies ResourceLeaseRepository;
}

function client(
  fetchImpl: typeof fetch,
  leases: null | ResourceLeaseRepository = leaseRepository(),
): Promise<GoogleOrgChartDriveClient> {
  return Promise.resolve(
    new GoogleOrgChartDriveClient({
      driveId: DRIVE_ID,
      fetchImpl,
      fileId: FILE_ID,
      ...(!(leases === null) && { leaseRepository: leases }),
      privateKey: testPrivateKey,
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    }),
  );
}

function standardDriveRead(url: string): null | Response {
  if (url.includes("oauth2.googleapis.com")) {
    return Response.json({ "access_token": "token", "expires_in": 3600 });
  }
  if (url.includes("/permissions?")) {
    return Response.json({ permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION] });
  }
  if (url.includes("/drive/v2/files/"))
    return Response.json(DRIVE_V2_FILE_ETAG);
  if (url.includes("fields=")) return Response.json(metadata);
  return null;
}

function upsert(
  drive: GoogleOrgChartDriveClient,
  html: string,
  expectedCurrentSha256 = EMPTY_HTML_SHA256,
) {
  return drive.upsert({ expectedCurrentSha256, html, runId: "run" });
}

async function sha256(content: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(content),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function legacyRenameFetch(state: {
  metadataReads: number;
  patches: { body: null | string; url: string }[];
}): typeof fetch {
  return async (input, init) => {
    const url = requestUrl(input);
    if (url.includes("oauth2.googleapis.com")) {
      return Response.json({ "access_token": "token", "expires_in": 3600 });
    }
    if (url.includes("/permissions?")) {
      return Response.json({
        permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
      });
    }
    if (url.includes("fields=")) {
      state.metadataReads++;
      return Response.json({
        ...metadata,
        name:
          state.metadataReads === 1
            ? "Sarj Organization Chart.html"
            : "Organization Chart",
      });
    }
    if (init?.method === "PUT") {
      state.patches.push({
        body: z.string().nullable().catch(null).parse(init.body),
        url,
      });
      return new Response(null, { status: 200 });
    }
    return new Response("<html></html>");
  };
}

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : String(input);
}

function driveOperation(url: string, method = "GET"): null | string {
  if (url.includes("googleapis.com/upload/drive/v2/"))
    return `${method} v2-upload`;
  if (!url.includes("googleapis.com/drive/")) return null;
  if (url.includes("/drive/v2/")) return `${method} v2-metadata`;
  if (url.includes("/permissions?")) return `${method} v3-permissions`;
  if (url.includes("alt=media")) return `${method} v3-media`;
  return `${method} v3-metadata`;
}

function successfulUpdateResponse(
  url: string,
  init: RequestInit | undefined,
  state: {
    downloads: number;
    patches: number;
    conditionalEtags: (null | string)[];
  },
): Response {
  const standard = init?.method === "PUT" ? null : standardDriveRead(url);
  if (standard) return standard;
  if (init?.method === "PUT") {
    state.patches++;
    state.conditionalEtags.push(new Headers(init.headers).get("if-match"));
    return new Response(null, { status: 200 });
  }
  state.downloads++;
  return new Response(
    state.downloads <= 2 ? "<html>old</html>" : "<html>new</html>",
  );
}

async function clientWithServiceAccountPermission(
  role: string,
): Promise<GoogleOrgChartDriveClient> {
  return client(async (input) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.includes("oauth2.googleapis.com")) {
      return Response.json({ "access_token": "token", "expires_in": 3600 });
    }
    if (url.includes("/permissions?")) {
      return Response.json({
        permissions: [
          {
            emailAddress: "org-sync@example.iam.gserviceaccount.com",
            id: "service-account",
            role,
            type: "user",
          },
        ],
      });
    }
    if (url.includes("fields=")) return Response.json(metadata);
    return new Response("<html></html>");
  });
}

describe("pinned Google Drive organization chart", () => {
  it("rejects signed file-ID drift before lease or provider access", async () => {
    const leases = leaseRepository();
    const fetchImpl = vi.fn<typeof fetch>();
    const drive = await client(fetchImpl, leases);
    await expect(
      drive.upsert({
        expectedFileId: "different-file",
        expectedCurrentSha256: EMPTY_HTML_SHA256,
        html: "<html>new</html>",
        runId: "run",
      }),
    ).rejects.toThrow("org_chart_artifact_identity_changed");
    expect(drive.fileId).toBe(FILE_ID);
    expect(leases.acquire).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it.each(["missing", "busy"] as const)(
    "rejects %s leases before provider access",
    async (kind) => {
      const leases = leaseRepository();
      leases.acquire.mockResolvedValue({ kind: "busy" });
      const fetchImpl = vi.fn<typeof fetch>();
      const drive = await client(fetchImpl, kind === "missing" ? null : leases);
      await expect(upsert(drive, "<html>new</html>")).rejects.toThrow(
        kind === "missing"
          ? "org_chart_artifact_lease_required"
          : "org_chart_artifact_lease_busy",
      );
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(leases.release).not.toHaveBeenCalled();
    },
  );

  it.each(["fenced", "expired"] as const)(
    "rejects %s authority at the final write boundary",
    async (kind) => {
      const leases = leaseRepository();
      if (kind === "expired") {
        const acquire = leases.acquire.getMockImplementation();
        if (acquire === undefined)
          throw new Error("missing fixture acquisition");
        leases.acquire.mockImplementation(async (...args) => {
          const acquired = await acquire(...args);
          if (acquired.kind !== "acquired")
            throw new Error("missing fixture lease");
          return {
            ...acquired,
            lease: activeResourceLease({ ...acquired.lease, expiresAtMs: 0 }),
          };
        });
      }
      leases.assertActive.mockImplementation(async (lease, remainingMs = 0) => {
        if (kind === "fenced" || lease.expiresAtMs < Date.now() + remainingMs)
          throw new ResourceLeaseFencedError(lease);
      });
      const state = {
        downloads: 0,
        patches: 0,
        conditionalEtags: [] as (null | string)[],
      };
      const drive = await client(
        async (input, init) =>
          successfulUpdateResponse(requestUrl(input), init, state),
        leases,
      );
      await expect(
        upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
      ).rejects.toThrow("resource_lease_fenced");
      expect(state).toMatchObject({ downloads: 2, patches: 0 });
      expect(leases.assertActive).toHaveBeenCalledOnce();
      expect(leases.release).toHaveBeenCalledOnce();
    },
  );

  it("keeps audit reads available without a mutation lease", async () => {
    const drive = await client(
      async (input) =>
        standardDriveRead(requestUrl(input)) ?? new Response("<html></html>"),
      null,
    );
    await expect(drive.readContentSha256("audit")).resolves.toBe(
      EMPTY_HTML_SHA256,
    );
  });

  it("rejects insufficient write/readback time after the final content preflight", async () => {
    const leases = leaseRepository();
    const state = {
      downloads: 0,
      patches: 0,
      conditionalEtags: [] as (null | string)[],
    };
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    try {
      const drive = await client(async (input, init) => {
        const response = successfulUpdateResponse(
          requestUrl(input),
          init,
          state,
        );
        if (state.downloads === 2) clock.mockReturnValue(now + 95_000);
        return response;
      }, leases);
      await expect(
        upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
      ).rejects.toThrow("org_chart_artifact_write_headroom_exhausted");
      expect(state.patches).toBe(0);
      expect(leases.assertActive).not.toHaveBeenCalled();
      expect(leases.release).toHaveBeenCalledOnce();
    } finally {
      clock.mockRestore();
    }
  });

  it("uses the same artifact lease across independent clients and preserves ETag/readback", async () => {
    const leases = leaseRepository();
    for (let run = 0; run < 2; run++) {
      const state = {
        downloads: 0,
        patches: 0,
        conditionalEtags: [] as (null | string)[],
      };

      const drive = await client(
        async (input, init) =>
          successfulUpdateResponse(requestUrl(input), init, state),
        leases,
      );

      await upsert(drive, "<html>new</html>", await sha256("<html>old</html>"));
      expect(state).toEqual({
        downloads: 3,
        patches: 1,
        conditionalEtags: ['"etag-v1"'],
      });
    }
    expect(leases.acquire.mock.calls[0]?.[0]).toBe(
      leases.acquire.mock.calls[1]?.[0],
    );
    expect(leases.acquire.mock.calls[0]?.[0]).toMatch(
      /^google-drive\/artifact\/[a-f0-9]{64}$/u,
    );
    expect(leases.release).toHaveBeenCalledTimes(2);
    expect(
      leases.assertActive.mock.calls.every(
        ([, remaining]) => (remaining ?? 0) >= 30_000,
      ),
    ).toBe(true);
  });

  it("releases after a provider failure without retrying the conditional write", async () => {
    const leases = leaseRepository();
    let writes = 0;
    const drive = await client(async (input, init) => {
      if (init?.method === "PUT") {
        writes++;
        return new Response(null, { status: 412 });
      }
      return (
        standardDriveRead(requestUrl(input)) ?? new Response("<html>old</html>")
      );
    }, leases);
    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).rejects.toThrow("ETag changed");
    expect(writes).toBe(1);
    expect(leases.release).toHaveBeenCalledOnce();
  });

  it("does not write when the exact pinned file is unchanged", async () => {
    const methods: string[] = [];
    const drive = await client(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      methods.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        return Response.json({
          permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
        });
      }
      if (url.includes("fields=")) return Response.json(metadata);
      return new Response("<html></html>");
    });
    await expect(upsert(drive, "<html></html>")).resolves.toMatchObject({
      action: "unchanged",
    });
    expect(methods.some((method) => method.startsWith("PUT "))).toBe(false);
  });

  it("accepts a hidden parent when Drive confirms the authoritative Shared Drive ID", async () => {
    const drive = await client(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        return Response.json({
          permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
        });
      }
      if (url.includes("fields="))
        return Response.json({ ...metadata, parents: [] });
      return new Response("<html></html>");
    });
    await expect(upsert(drive, "<html></html>")).resolves.toMatchObject({
      action: "unchanged",
    });
  });

  it("does not require an ETag for a read-only content audit", async () => {
    const drive = await client(async (input) => {
      const url = requestUrl(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        return Response.json({
          permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
        });
      }
      if (url.includes("fields=")) {
        return Response.json(metadata);
      }
      return new Response("<html></html>");
    });

    await expect(drive.readContentSha256("run")).resolves.toBe(
      "b633a587c652d02386c4f16f8c6f6aab7352d97f16367c3c40576214372dd628",
    );
  });

  it("fails closed before mutation when Drive v2 omits its concurrency ETag", async () => {
    let patches = 0;
    const drive = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        return Response.json({
          permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
        });
      }
      if (url.includes("/drive/v2/files/"))
        return Response.json({ id: FILE_ID });
      if (url.includes("fields=")) return Response.json(metadata);
      if (init?.method === "PUT") {
        patches++;
        return new Response(null, { status: 200 });
      }
      return new Response("<html>old</html>");
    });

    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).rejects.toThrow(
      "Pinned Google Drive org chart version response omitted a valid ETag",
    );
    expect(patches).toBe(0);
  });

  it("updates once and requires exact read-back", async () => {
    const state = {
      conditionalEtags: [] as (null | string)[],
      downloads: 0,
      patches: 0,
    };
    const driveOperations: string[] = [];
    const drive = await client((input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      const operation = driveOperation(url, init?.method);
      if (operation !== null) driveOperations.push(operation);
      return Promise.resolve(successfulUpdateResponse(url, init, state));
    });
    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).resolves.toMatchObject({
      action: "updated",
      fileId: FILE_ID,
    });
    expect(state.patches).toBe(1);
    expect(state.downloads).toBe(3);
    expect(state.conditionalEtags).toEqual([DRIVE_V2_FILE_ETAG.etag]);
    expect(driveOperations).toEqual([
      "GET v3-metadata",
      "GET v3-permissions",
      "GET v3-media",
      "GET v2-metadata",
      "GET v3-media",
      "PUT v2-upload",
      "GET v3-media",
    ]);
  });

  it("fails closed when content drifts after binding the ETag", async () => {
    let downloads = 0;
    let writes = 0;
    const drive = await client(async (input, init) => {
      const url = requestUrl(input);
      const standard = init?.method === "PUT" ? null : standardDriveRead(url);
      if (standard) return standard;
      if (init?.method === "PUT") {
        writes++;
        return new Response(null, { status: 200 });
      }
      downloads++;
      return new Response(
        downloads === 1 ? "<html>old</html>" : "<html>concurrent</html>",
      );
    });

    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).rejects.toThrow(/changed while binding/);
    expect(writes).toBe(0);
    expect(downloads).toBe(2);
  });

  it("fails closed when Drive v2 returns another file identity", async () => {
    let writes = 0;
    const drive = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        return Response.json({
          permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
        });
      }
      if (url.includes("/drive/v2/files/")) {
        return Response.json({ ...DRIVE_V2_FILE_ETAG, id: "another-file" });
      }
      if (url.includes("fields=")) return Response.json(metadata);
      if (init?.method === "PUT") {
        writes++;
        return new Response(null, { status: 200 });
      }
      return new Response("<html>old</html>");
    });

    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).rejects.toThrow(/unexpected versioned file/);
    expect(writes).toBe(0);
  });

  it("converges without a second write", async () => {
    let content = "<html>old</html>";
    let writes = 0;
    const drive = await client(async (input, init) => {
      const url = requestUrl(input);
      const standard = init?.method === "PUT" ? null : standardDriveRead(url);
      if (standard) return standard;
      if (init?.method === "PUT") {
        writes++;
        content = z.string().catch("").parse(init.body);
        return new Response(null, { status: 200 });
      }
      return new Response(content);
    });

    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).resolves.toMatchObject({ action: "updated" });
    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>new</html>")),
    ).resolves.toMatchObject({ action: "unchanged" });
    expect(writes).toBe(1);
  });

  it("fails closed on an ETag race without retrying or reading back", async () => {
    let downloads = 0;
    const conditionalEtags: (null | string)[] = [];
    const drive = await client(async (input, init) => {
      const url = requestUrl(input);
      const standard = init?.method === "PUT" ? null : standardDriveRead(url);
      if (standard) return standard;
      if (init?.method === "PUT") {
        conditionalEtags.push(new Headers(init.headers).get("if-match"));
        return new Response(null, { status: 412 });
      }
      downloads++;
      return new Response("<html>old</html>");
    });

    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).rejects.toThrow(/ETag changed/);
    expect(conditionalEtags).toEqual([DRIVE_V2_FILE_ETAG.etag]);
    expect(downloads).toBe(2);
  });

  it("never retries an ambiguous Drive update failure", async () => {
    let writes = 0;
    const drive = await client(async (input, init) => {
      const url = requestUrl(input);
      const standard = init?.method === "PUT" ? null : standardDriveRead(url);
      if (standard) return standard;
      if (init?.method === "PUT") {
        writes++;
        return new Response(null, { status: 503 });
      }
      return new Response("<html>old</html>");
    });

    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>old</html>")),
    ).rejects.toThrow(/files\.update HTTP 503/);
    expect(writes).toBe(1);
  });

  it("rejects content drift before any Drive mutation", async () => {
    let writes = 0;
    const drive = await client(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      const standard = init?.method === "PUT" ? null : standardDriveRead(url);
      if (standard) return standard;
      if (init?.method === "PUT") {
        writes++;
        return new Response(null, { status: 200 });
      }
      return new Response("<html>changed-after-plan</html>");
    });

    await expect(
      upsert(drive, "<html>desired</html>", "0".repeat(64)),
    ).rejects.toThrow(/changed after planning/);
    expect(writes).toBe(0);
  });

  it("accepts the pinned legacy filename without an unplanned metadata write", async () => {
    const state = {
      metadataReads: 0,
      patches: [] as { body: null | string; url: string }[],
    };
    const drive = await client(legacyRenameFetch(state));

    await expect(upsert(drive, "<html></html>")).resolves.toMatchObject({
      action: "unchanged",
    });
    expect(state.metadataReads).toBe(1);
    expect(state.patches).toEqual([]);
  });

  it.each([
    {
      message: /moved out/,
      metadata: { ...metadata, driveId: "another-drive", parents: [] },
    },
    {
      message: /moved from/,
      metadata: { ...metadata, parents: ["nested-folder"] },
    },
    { message: /renamed/, metadata: { ...metadata, name: "Another.html" } },
    { message: /MIME/, metadata: { ...metadata, mimeType: "text/plain" } },
    { message: /trashed/, metadata: { ...metadata, trashed: true } },
  ])("fails closed for pinned file drift: $message", async (scenario) => {
    const drive = await client(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        return Response.json({
          permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
        });
      }
      return Response.json(scenario.metadata);
    });
    await expect(upsert(drive, "<html></html>")).rejects.toThrow(
      scenario.message,
    );
  });
  it("fails closed when the pinned file is missing", async () => {
    const missing = await client(async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      return new Response(null, { status: 404 });
    });
    await expect(upsert(missing, "<html></html>")).rejects.toThrow(
      /unavailable.*404/,
    );
  });

  it("fails when Drive acknowledges an update but read-back differs", async () => {
    const drive = await client(async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      const standard = init?.method === "PUT" ? null : standardDriveRead(url);
      if (standard) return standard;
      if (init?.method === "PUT") return new Response(null, { status: 200 });
      return new Response("<html>stale</html>");
    });
    await expect(
      upsert(drive, "<html>new</html>", await sha256("<html>stale</html>")),
    ).rejects.toThrow(/read-back mismatch/);
  });

  it("rejects direct public and external permissions before reading content", async () => {
    for (const permission of [
      { id: "public", role: "reader", type: "anyone" },
      {
        id: "inherited-public",
        permissionDetails: [{ inheritedFrom: DRIVE_ID }],
        role: "reader",
        type: "anyone",
      },
      { domain: "example.com", id: "domain", role: "reader", type: "domain" },
      {
        emailAddress: "outside@example.com",
        id: "user",
        role: "reader",
        type: "user",
      },
      { id: "unverifiable", role: "reader", type: "group" },
    ]) {
      const drive = await client(async (input) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.includes("oauth2.googleapis.com")) {
          return Response.json({ "access_token": "token", "expires_in": 3600 });
        }
        if (url.includes("/permissions?"))
          return Response.json({ permissions: [permission] });
        return Response.json(metadata);
      });
      await expect(upsert(drive, "<html></html>")).rejects.toThrow(
        /public|external|unverifiable/,
      );
    }
  });

  it("rejects an external permission discovered on a later page", async () => {
    const permissionUrls: string[] = [];
    const drive = await client(async (input) => {
      const url = requestUrl(input);
      if (url.includes("oauth2.googleapis.com")) {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.includes("/permissions?")) {
        permissionUrls.push(url);
        if (!url.includes("pageToken=")) {
          return Response.json({
            nextPageToken: "page-2",
            permissions: [SERVICE_ACCOUNT_WRITER_PERMISSION],
          });
        }
        return Response.json({
          permissions: [
            {
              emailAddress: "outside@example.com",
              id: "external",
              role: "reader",
              type: "user",
            },
          ],
        });
      }
      return Response.json(metadata);
    });

    await expect(upsert(drive, "<html></html>")).rejects.toThrow(/external/);
    expect(permissionUrls).toHaveLength(2);
    expect(permissionUrls[1]).toContain("pageToken=page-2");
  });

  it("allows the configured service account as an external writer", async () => {
    const drive = await clientWithServiceAccountPermission("writer");
    await expect(upsert(drive, "<html></html>")).resolves.toMatchObject({
      action: "unchanged",
    });
  });

  it("rejects the configured service account without writer access", async () => {
    const drive = await clientWithServiceAccountPermission("reader");
    await expect(upsert(drive, "<html></html>")).rejects.toThrow(
      /service account is not a writer/,
    );
  });
});
