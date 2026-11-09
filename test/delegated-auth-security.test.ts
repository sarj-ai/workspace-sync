import { decodeJwt, exportPKCS8, generateKeyPair } from "jose";
import { describe, expect, it, vi } from "vitest";

import { GoogleDelegatedAuth } from "../src/org-sync/google-delegated-auth.ts";
import { GoogleDirectoryClient } from "../src/org-sync/google-directory-client.ts";
import { GoogleOrgChartDriveClient } from "../src/org-sync/google-org-chart-drive-client.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

describe("delegated Google authentication", () => {
  it("keeps direct Drive assertions free of delegated administrator subjects", async () => {
    let assertion: ReturnType<typeof decodeJwt> | undefined;
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      if (!(init?.body instanceof URLSearchParams))
        throw new TypeError("Expected an OAuth form body");
      const value = init.body.get("assertion");
      if (!value) throw new Error("Missing assertion");
      assertion = decodeJwt(value);
      return new Response(null, { status: 403 });
    });
    const drive = new GoogleOrgChartDriveClient({
      driveId: "synthetic-drive",
      fileId: "synthetic-file",
      userProject: "synthetic-project",
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "sync@example.iam.gserviceaccount.com",
      fetchImpl,
    });
    await expect(drive.readContentSha256("run")).rejects.toThrow("HTTP 403");
    expect(assertion).toMatchObject({
      iss: "sync@example.iam.gserviceaccount.com",
      scope: "https://www.googleapis.com/auth/drive",
    });
    expect(assertion).not.toHaveProperty("sub");
  });

  it.each([0, -1, 3601, Number["MAX_SAFE_INTEGER"]])(
    "rejects OAuth lifetime %s without leaking the returned token",
    async (expiresIn) => {
      const auth = new GoogleDelegatedAuth({
        adminSubject: "admin@example.com",
        serviceAccountEmail: "sync@example.iam.gserviceaccount.com",
        privateKey: await rsaPrivateKeyFixture(),
        fetchImpl: async () =>
          Response.json({
            "access_token": "secret-sentinel",
            "expires_in": expiresIn,
          }),
      });
      const request = auth.accessToken("readonly-test-scope", "run");
      await expect(request).rejects.toThrow(
        "google_oauth_invalid_token_response",
      );
      await expect(request).rejects.not.toHaveProperty("cause");
    },
  );

  it("rejects an oversized OAuth response before buffering the complete stream", async () => {
    const cancel = vi.fn();
    const auth = new GoogleDelegatedAuth({
      adminSubject: "admin@example.com",
      serviceAccountEmail: "sync@example.iam.gserviceaccount.com",
      privateKey: await rsaPrivateKeyFixture(),
      fetchImpl: async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array(16_385));
            },
            cancel,
          }),
        ),
    });
    await expect(
      auth.accessToken("readonly-test-scope", "run"),
    ).rejects.toThrow("google_oauth_response_too_large");
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("rejects writes with the default Directory scope before authenticating or dispatching", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const directory = new GoogleDirectoryClient({
      adminSubject: "admin@example.com",
      privateKey: "unused-test-key",
      serviceAccountEmail: "sync@example.iam.gserviceaccount.com",
      userProject: "workspace-sync-test",
      fetchImpl,
    });
    await expect(
      directory.setLinkedInDigestOptOut(
        "100000000000000000020",
        true,
        "1700000000.000001",
        "etag",
        "test-run",
      ),
    ).rejects.toThrow("require the writable user scope");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("binds signed assertions to the configured tenant, scope and audience and isolates token caches by scope", async () => {
    const { privateKey } = await generateKeyPair("RS256", {
      extractable: true,
    });
    const assertions: ReturnType<typeof decodeJwt>[] = [];
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockImplementation(async (_input, init) => {
        if (!(init?.body instanceof URLSearchParams))
          throw new TypeError("Expected an OAuth form body");
        const body = init.body;
        const assertion = body.get("assertion");
        if (assertion === null) throw new Error("Missing test assertion");
        assertions.push(decodeJwt(assertion));
        expect(init.redirect).toBe("manual");
        return Response.json({
          "access_token": `test-token-${String(assertions.length)}`,
          "expires_in": 3600,
        });
      });
    const options = {
      adminSubject: "admin@example.com",
      privateKey: await exportPKCS8(privateKey),
      serviceAccountEmail: "sync@example.iam.gserviceaccount.com",
      fetchImpl,
    };
    const auth = new GoogleDelegatedAuth(options);
    options.adminSubject = "changed@example.com";
    const readonlyScope =
      "https://www.googleapis.com/auth/admin.directory.user.readonly";
    await expect(auth.accessToken(readonlyScope, "test-run")).resolves.toBe(
      "test-token-1",
    );
    await expect(auth.accessToken(readonlyScope, "test-run")).resolves.toBe(
      "test-token-1",
    );
    await expect(
      auth.accessToken(
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "test-run",
      ),
    ).resolves.toBe("test-token-2");
    expect(assertions).toHaveLength(2);
    expect(assertions[0]).toMatchObject({
      iss: "sync@example.iam.gserviceaccount.com",
      sub: "admin@example.com",
      aud: "https://oauth2.googleapis.com/token",
      scope: readonlyScope,
    });
    expect((assertions[0]?.exp ?? 0) - (assertions[0]?.iat ?? 0)).toBe(3600);
  });
});
