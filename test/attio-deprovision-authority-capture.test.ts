import { describe, expect, it, vi } from "vitest";

import {
  AttioDeprovisionAuthorityCapture,
  AttioDeprovisionAuthorityCaptureError,
} from "../src/identity-provisioning/attio-deprovision-authority-capture.ts";

const WORKSPACE_ID = "e41575c4-362a-4be5-9bed-f3faaade5597";
const OTHER_WORKSPACE_ID = "018f47e2-8f3f-70c2-8000-000000000001";
const MEMBER_ID = "50cf242c-7fa3-4cad-87d0-75b1af71c57b";
const INVITE_ID = "3a8f5b2c-9e14-4d7a-b832-1c6f85d90e47";
const CAPTURED_AT = "2026-09-01T00:00:00.000Z";

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : input.toString();
}

function tokenMetadata(overrides: Record<string, unknown> = {}) {
  return {
    active: true,
    "additive_provider_field": "tolerated",
    scope: "user_management:read",
    "token_type": "Bearer",
    "workspace_id": WORKSPACE_ID,
    ...overrides,
  };
}

function scimUser(id: string, email: string) {
  return {
    active: true,
    "avatar_url": "https://example.com/avatar.png",
    appRole: "member",
    emails: [{ primary: true, type: "work", value: email }],
    id,
    meta: {
      created: "2026-08-01T00:00:00.000Z",
      lastModified: "2026-08-02T00:00:00.000Z",
      resourceType: "User",
    },
    name: { familyName: "User", givenName: "Sarj" },
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: email,
  };
}

function scimPage(
  resources: readonly ReturnType<typeof scimUser>[],
  options: { startIndex: number; totalResults: number },
) {
  return {
    Resources: resources,
    "additive_provider_field": "tolerated",
    itemsPerPage: resources.length,
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    startIndex: options.startIndex,
    totalResults: options.totalResults,
  };
}

function workspaceMember(
  workspaceId = WORKSPACE_ID,
  accessLevel: "admin" | "member" | "suspended" = "member",
) {
  return {
    "access_level": accessLevel,
    "avatar_url": "https://example.com/avatar.png",
    "email_address": "member@company.test",
    "first_name": "Sarj",
    id: { "workspace_id": workspaceId, "workspace_member_id": MEMBER_ID },
    "last_name": "Member",
  };
}

function sourceError(error: unknown) {
  if (!(error instanceof AttioDeprovisionAuthorityCaptureError)) {
    throw new Error("expected AttioDeprovisionAuthorityCaptureError", {
      cause: error,
    });
  }
  return error;
}

describe("Attio deprovision authority capture", () => {
  it("pins the read-only token and captures complete paginated SCIM and member authority", async () => {
    const urls: string[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(init).toMatchObject({
        headers: { authorization: "Bearer read-token" },
        method: "GET",
      });
      const url = new URL(requestUrl(input));
      urls.push(url.toString());
      if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
      if (url.pathname === "/v2/workspace_members") {
        return Response.json({ data: [workspaceMember()] });
      }
      const startIndex = Number(url.searchParams.get("startIndex"));
      expect(url.searchParams.get("count")).toBe("100");
      return Response.json(
        startIndex === 1
          ? scimPage([scimUser(MEMBER_ID, "MEMBER@COMPANY.TEST")], {
              startIndex: 1,
              totalResults: 2,
            })
          : scimPage([scimUser(INVITE_ID, "invite@company.test")], {
              startIndex: 2,
              totalResults: 2,
            }),
      );
    });

    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      now: () => new Date(CAPTURED_AT),
    });

    await expect(capture.capture()).resolves.toEqual({
      capturedAt: CAPTURED_AT,
      complete: true,
      scimStatus: "available",
      scimUsers: [
        {
          active: true,
          appRole: "member",
          emails: [{ primary: true, value: "member@company.test" }],
          id: MEMBER_ID,
          lastModified: "2026-08-02T00:00:00.000Z",
          userName: "member@company.test",
        },
        {
          active: true,
          appRole: "member",
          emails: [{ primary: true, value: "invite@company.test" }],
          id: INVITE_ID,
          lastModified: "2026-08-02T00:00:00.000Z",
          userName: "invite@company.test",
        },
      ],
      token: { scopes: ["user_management:read"], workspaceId: WORKSPACE_ID },
      workspaceMembers: [
        {
          accessLevel: "member",
          emailAddress: "member@company.test",
          id: { workspaceId: WORKSPACE_ID, workspaceMemberId: MEMBER_ID },
        },
      ],
    });
    expect(urls[0]?.endsWith("/v2/self")).toBe(true);
    expect(urls).toEqual(
      expect.arrayContaining([
        expect.stringContaining("/scim/v2/Users?count=100&startIndex=1"),
        expect.stringContaining("/scim/v2/Users?count=100&startIndex=2"),
        expect.stringContaining("/v2/workspace_members"),
      ]),
    );
  });

  it("captures REST authority and records the explicit connector gap when SCIM requires payment", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(requestUrl(input));
      if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
      if (url.pathname === "/v2/workspace_members") {
        return Response.json({ data: [workspaceMember()] });
      }
      return Response.json({ detail: "payment required" }, { status: 402 });
    });

    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      now: () => new Date(CAPTURED_AT),
    });

    await expect(capture.capture()).resolves.toMatchObject({
      complete: true,
      scimStatus: "payment-required",
      scimUsers: [],
      workspaceMembers: [expect.objectContaining({ accessLevel: "member" })],
    });
  });

  it("captures Attio suspended workspace members without rejecting the complete inventory", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(requestUrl(input));
      if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
      if (url.pathname === "/v2/workspace_members") {
        return Response.json({
          data: [workspaceMember(WORKSPACE_ID, "suspended")],
        });
      }
      return Response.json(
        scimPage([scimUser(MEMBER_ID, "member@company.test")], {
          startIndex: 1,
          totalResults: 1,
        }),
      );
    });

    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      now: () => new Date(CAPTURED_AT),
    });

    const result = await capture.capture();
    expect(result.workspaceMembers).toEqual([
      expect.objectContaining({ accessLevel: "suspended" }),
    ]);
  });

  it.each([
    [
      tokenMetadata({
        active: false,
        scope: undefined,
        "token_type": undefined,
        "workspace_id": undefined,
      }),
      "token-inactive",
    ],
    [
      tokenMetadata({ "workspace_id": OTHER_WORKSPACE_ID }),
      "workspace-mismatch",
    ],
    [
      tokenMetadata({
        scope: "user_management:read object_configuration:read",
      }),
      "scope-mismatch",
    ],
    [tokenMetadata({ scope: "user_management:read-write" }), "scope-mismatch"],
  ] as const)(
    "fails closed on unsafe token metadata",
    async (metadata, code) => {
      const fetchImpl = vi.fn<typeof fetch>(async () =>
        Response.json(metadata),
      );
      const capture = new AttioDeprovisionAuthorityCapture({
        apiKey: "read-token",
        expectedWorkspaceId: WORKSPACE_ID,
        fetchImpl,
      });
      const error = sourceError(
        await capture.capture().catch((caught: unknown) => caught),
      );
      expect(error).toMatchObject({ code, component: "token-metadata" });
      expect(fetchImpl).toHaveBeenCalledOnce();
    },
  );

  it("rejects invalid configuration without reading Attio", () => {
    const fetchImpl = vi.fn<typeof fetch>();
    expect(
      () =>
        new AttioDeprovisionAuthorityCapture({
          apiKey: "",
          expectedWorkspaceId: "not-a-uuid",
          fetchImpl,
        }),
    ).toThrow(
      expect.objectContaining({
        code: "configuration-invalid",
        component: "configuration",
      }),
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    [
      "wrong start index",
      scimPage([scimUser(MEMBER_ID, "member@company.test")], {
        startIndex: 2,
        totalResults: 2,
      }),
    ],
    [
      "changed total",
      scimPage([scimUser(INVITE_ID, "invite@company.test")], {
        startIndex: 2,
        totalResults: 3,
      }),
    ],
    ["empty early page", scimPage([], { startIndex: 2, totalResults: 2 })],
  ] as const)("rejects invalid SCIM pagination: %s", async (label, badPage) => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(requestUrl(input));
      if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
      if (url.pathname === "/v2/workspace_members")
        return Response.json({ data: [] });
      return Response.json(
        url.searchParams.get("startIndex") === "1" &&
          label !== "wrong start index"
          ? scimPage([scimUser(MEMBER_ID, "member@company.test")], {
              startIndex: 1,
              totalResults: 2,
            })
          : badPage,
      );
    });
    const error = sourceError(
      await new AttioDeprovisionAuthorityCapture({
        apiKey: "read-token",
        expectedWorkspaceId: WORKSPACE_ID,
        fetchImpl,
        sleep: async () => undefined,
      })
        .capture()
        .catch((caught: unknown) => caught),
    );
    expect(error).toMatchObject({
      code: "scim-pagination-invalid",
      component: "scim-users",
    });
  });

  it("bounds SCIM pagination", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(requestUrl(input));
      if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
      if (url.pathname === "/v2/workspace_members")
        return Response.json({ data: [] });
      return Response.json(
        scimPage([scimUser(MEMBER_ID, "member@company.test")], {
          startIndex: 1,
          totalResults: 2,
        }),
      );
    });
    const error = sourceError(
      await new AttioDeprovisionAuthorityCapture({
        apiKey: "read-token",
        expectedWorkspaceId: WORKSPACE_ID,
        fetchImpl,
        maxPages: 1,
      })
        .capture()
        .catch((caught: unknown) => caught),
    );
    expect(error).toMatchObject({
      code: "scim-page-limit-exceeded",
      component: "scim-users",
    });
  });

  it("rejects duplicate SCIM IDs and cross-tenant or duplicate workspace member IDs", async () => {
    const cases = [
      {
        code: "scim-duplicate-user-id",
        members: [],
        users: [
          scimUser(MEMBER_ID, "one@company.test"),
          scimUser(MEMBER_ID, "two@company.test"),
        ],
      },
      {
        code: "workspace-mismatch",
        members: [workspaceMember(OTHER_WORKSPACE_ID)],
        users: [],
      },
      {
        code: "workspace-member-duplicate-id",
        members: [workspaceMember(), workspaceMember()],
        users: [scimUser(MEMBER_ID, "member@company.test")],
      },
    ] as const;
    for (const testCase of cases) {
      const fetchImpl = vi.fn<typeof fetch>(async (input) => {
        const url = new URL(requestUrl(input));
        if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
        if (url.pathname === "/v2/workspace_members") {
          return Response.json({ data: testCase.members });
        }
        return Response.json(
          scimPage(testCase.users, {
            startIndex: 1,
            totalResults: testCase.users.length,
          }),
        );
      });
      const error = sourceError(
        await new AttioDeprovisionAuthorityCapture({
          apiKey: "read-token",
          expectedWorkspaceId: WORKSPACE_ID,
          fetchImpl,
        })
          .capture()
          .catch((caught: unknown) => caught),
      );
      expect(error.code).toBe(testCase.code);
    }
  });

  it("retains manually managed workspace members outside the SCIM authority", async () => {
    const member = workspaceMember();
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(requestUrl(input));
      if (url.pathname === "/v2/self") return Response.json(tokenMetadata());
      if (url.pathname === "/v2/workspace_members")
        return Response.json({ data: [member] });
      return Response.json(scimPage([], { startIndex: 1, totalResults: 0 }));
    });

    await expect(
      new AttioDeprovisionAuthorityCapture({
        apiKey: "read-token",
        expectedWorkspaceId: WORKSPACE_ID,
        fetchImpl,
      }).capture(),
    ).resolves.toMatchObject({
      scimUsers: [],
      workspaceMembers: [expect.any(Object)],
    });
  });

  it.each([
    [
      "HTTP status",
      async () => new Response(null, { status: 503 }),
      "source-http",
    ],
    [
      "transport failure",
      async () => {
        throw new Error("network down");
      },
      "source-unavailable",
    ],
    ["malformed JSON", async () => new Response("{"), "source-invalid"],
    [
      "oversized response",
      async () =>
        new Response("{}", { headers: { "content-length": "2097153" } }),
      "response-oversized",
    ],
    [
      "chunked oversized response",
      async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array(2 * 1_024 * 1_024));
              controller.enqueue(new Uint8Array(1));
              controller.close();
            },
          }),
        ),
      "response-oversized",
    ],
    [
      "schema failure",
      async () => Response.json(tokenMetadata({ "token_type": "Basic" })),
      "source-invalid",
    ],
  ] as const)(
    "returns a stable source error for %s",
    async (_label, responder, code) => {
      const fetchImpl = vi.fn<typeof fetch>(responder);
      const error = sourceError(
        await new AttioDeprovisionAuthorityCapture({
          apiKey: "read-token",
          expectedWorkspaceId: WORKSPACE_ID,
          fetchImpl,
          sleep: async () => undefined,
        })
          .capture()
          .catch((caught: unknown) => caught),
      );
      expect(error).toMatchObject({ code, component: "token-metadata" });
      expect(error.message).not.toContain("network down");
    },
  );

  it("retries transient reads with Retry-After while honoring one capture deadline", async () => {
    const waits: number[] = [];
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(null, { headers: { "retry-after": "2" }, status: 429 }),
      )
      .mockResolvedValueOnce(Response.json(tokenMetadata()))
      .mockImplementation(async (input) => {
        const url = new URL(requestUrl(input));
        if (url.pathname === "/v2/workspace_members")
          return Response.json({ data: [] });
        return Response.json(scimPage([], { startIndex: 1, totalResults: 0 }));
      });
    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      random: () => 0,
      sleep: async (milliseconds) => {
        waits.push(milliseconds);
      },
    });

    await expect(
      capture.capture(Date.now() + 30_000, "run-123"),
    ).resolves.toMatchObject({
      complete: true,
    });
    expect(waits).toEqual([2_000]);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
    for (const [, init] of fetchImpl.mock.calls)
      expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("honors an HTTP-date Retry-After used by Attio rate limits", async () => {
    const waits: number[] = [];
    const retryAt = new Date(Date.now() + 12_000).toUTCString();
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(null, {
          headers: { "retry-after": retryAt },
          status: 429,
        }),
      )
      .mockResolvedValueOnce(Response.json(tokenMetadata()))
      .mockImplementation(async (input) => {
        const url = new URL(requestUrl(input));
        if (url.pathname === "/v2/workspace_members")
          return Response.json({ data: [] });
        return Response.json(scimPage([], { startIndex: 1, totalResults: 0 }));
      });
    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      random: () => 0,
      sleep: async (milliseconds) => {
        waits.push(milliseconds);
      },
    });

    await expect(
      capture.capture(Date.now() + 30_000, "run-date"),
    ).resolves.toMatchObject({
      complete: true,
    });
    expect(waits).toHaveLength(1);
    expect(waits[0]).toBeGreaterThanOrEqual(10_500);
    expect(waits[0]).toBeLessThanOrEqual(12_000);
  });

  it("bounds provider Retry-After when no capture deadline is supplied", async () => {
    const waits: number[] = [];
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(null, {
          headers: { "retry-after": "86400" },
          status: 429,
        }),
      )
      .mockResolvedValueOnce(Response.json(tokenMetadata()))
      .mockImplementation(async (input) => {
        const url = new URL(requestUrl(input));
        if (url.pathname === "/v2/workspace_members")
          return Response.json({ data: [] });
        return Response.json(scimPage([], { startIndex: 1, totalResults: 0 }));
      });
    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      sleep: async (milliseconds) => {
        waits.push(milliseconds);
      },
    });
    await expect(capture.capture()).resolves.toMatchObject({ complete: true });
    expect(waits).toEqual([8000]);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });

  it("fails before a provider read when the shared capture deadline is exhausted", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const capture = new AttioDeprovisionAuthorityCapture({
      apiKey: "read-token",
      expectedWorkspaceId: WORKSPACE_ID,
      fetchImpl,
      sleep: async () => undefined,
    });

    const error = sourceError(
      await capture
        .capture(Date.now() - 1, "run-expired")
        .catch((caught: unknown) => caught),
    );
    expect(error).toMatchObject({
      code: "deadline-exceeded",
      component: "token-metadata",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
