import { describe, expect, it, vi } from "vitest";

import {
  PagerDutyTeamReader,
  PagerDutyTeamRequestError,
  PagerDutyTeamUnexpectedMutationStatusError,
} from "../src/workspace-directory/pagerduty-team-client.ts";

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  return input instanceof Request ? input.url : input.toString();
}

function requireRequestInput(
  input: Parameters<typeof fetch>[0] | undefined,
): Parameters<typeof fetch>[0] {
  if (input === undefined) throw new Error("expected provider request");
  return input;
}

describe("PagerDuty team reader", () => {
  it("reads bounded license evidence without returning allocation identities or treating unlimited as free", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) =>
      requestUrl(input).endsWith("/licenses")
        ? json({
            licenses: [
              {
                id: "PLICENSE",
                "valid_roles": ["user"],
                "current_value": 1,
                "allocations_available": null,
                name: "private subscription",
                "html_url": "https://private.example.com",
              },
            ],
          })
        : json({
            limit: 100,
            more: false,
            offset: 0,
            "license_allocations": [
              { user: { id: "PPRIVATEUSER" }, license: { id: "PLICENSE" } },
            ],
          }),
    );
    const evidence = await new PagerDutyTeamReader({
      fetchImpl,
      token: "dedicated-token",
    }).licensing();
    expect(evidence).toEqual({
      licenses: [
        {
          id: "PLICENSE",
          "valid_roles": ["user"],
          "current_value": 1,
          "allocations_available": null,
        },
      ],
      allocationCount: 1,
    });
    expect(JSON.stringify(evidence)).not.toMatch(
      /PPRIVATEUSER|private|dedicated-token/u,
    );
    expect(
      fetchImpl.mock.calls.map(([url, init]) => ({
        path: new URL(requestUrl(url)).pathname,
        method: init?.method ?? "GET",
        redirect: init?.redirect,
      })),
    ).toEqual([
      { path: "/licenses", method: "GET", redirect: "manual" },
      { path: "/license_allocations", method: "GET", redirect: "manual" },
    ]);
  });

  it.each([307, 308])(
    "rejects a real %s license redirect without forwarding credentials",
    async (status) => {
      const fetchImpl = vi.fn<typeof fetch>(
        async () =>
          new Response(null, {
            status,
            headers: { location: "https://untrusted.example/licenses" },
          }),
      );
      await expect(
        new PagerDutyTeamReader({
          fetchImpl,
          token: "dedicated-token",
        }).licensing(),
      ).rejects.toThrow(`pagerduty_team_sync_http_${String(status)}`);
      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(fetchImpl.mock.calls[0]?.[1]?.redirect).toBe("manual");
    },
  );

  it("rejects duplicate license allocations and bounded pagination exhaustion", async () => {
    const allocation = { user: { id: "PUSER" }, license: { id: "PLICENSE" } };
    const fetchImpl = vi.fn<typeof fetch>(async (input) =>
      requestUrl(input).endsWith("/licenses")
        ? json({
            licenses: [
              {
                id: "PLICENSE",
                "valid_roles": ["user"],
                "current_value": 1,
                "allocations_available": 0,
              },
            ],
          })
        : json({
            limit: 100,
            more: false,
            offset: 0,
            "license_allocations": [allocation, allocation],
          }),
    );
    await expect(
      new PagerDutyTeamReader({
        fetchImpl,
        token: "dedicated-token",
      }).licensing(),
    ).rejects.toThrow("pagerduty_license_allocation_incomplete");
    const exhausted = vi.fn<typeof fetch>(async (input) =>
      requestUrl(input).endsWith("/licenses")
        ? json({ licenses: [] })
        : json({
            limit: 100,
            more: true,
            offset: 0,
            "license_allocations": [],
          }),
    );
    await expect(
      new PagerDutyTeamReader({
        fetchImpl: exhausted,
        maxPages: 1,
        token: "dedicated-token",
      }).licensing(),
    ).rejects.toThrow("pagerduty_team_sync_page_limit_exceeded");
  });

  it("checks final authority before dispatching the single membership write", async () => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response(null, { status: 204 }),
    );
    const writer = new PagerDutyTeamReader({ fetchImpl, token: "test-token" });
    const denied = vi.fn(async () => {
      throw new Error("authority expired");
    });
    await expect(
      writer.putTeamMembership("PTEAM", "PUSER", "responder", denied),
    ).rejects.toThrow("authority expired");
    expect(denied).toHaveBeenCalledOnce();
    expect(fetchImpl).not.toHaveBeenCalled();
    const allowed = vi.fn(async () => {
      expect(fetchImpl).not.toHaveBeenCalled();
    });
    await writer.putTeamMembership("PTEAM", "PUSER", "responder", allowed);
    expect(allowed).toHaveBeenCalledOnce();
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("reads bounded paginated users, teams, and exact team memberships", async () => {
    const requests: string[] = [];
    const responses = new Map<string, unknown>([
      [
        "/users?limit=100&offset=0",
        {
          limit: 1,
          more: true,
          offset: 0,
          users: [
            { email: "B@EXAMPLE.COM", id: "PUSER2", name: "B", role: "user" },
          ],
        },
      ],
      [
        "/users?limit=100&offset=1",
        {
          limit: 1,
          more: false,
          offset: 1,
          users: [
            { email: "a@example.com", id: "PUSER1", name: "A", role: "admin" },
          ],
        },
      ],
      [
        "/teams?limit=100&offset=0",
        {
          limit: 100,
          more: false,
          offset: 0,
          teams: [{ id: "PTEAM1", name: "Platform" }],
        },
      ],
      [
        "/teams/PTEAM1/members?limit=100&offset=0",
        {
          limit: 100,
          members: [{ role: "responder", user: { id: "PUSER2" } }],
          more: false,
          offset: 0,
        },
      ],
    ]);
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = requestUrl(input);
      requests.push(url);
      const headers = new Headers(init?.headers);
      expect(headers.get("accept")).toBe(
        "application/vnd.pagerduty+json;version=2",
      );
      expect(headers.get("authorization")).toBe("Token token=test-token");
      const response = [...responses].find(([suffix]) => url.endsWith(suffix));
      if (response) return json(response[1]);
      throw new Error(`unexpected request: ${url}`);
    });

    const snapshot = await new PagerDutyTeamReader({
      fetchImpl,
      token: "test-token",
    }).snapshot(["PTEAM1"]);

    expect(requests).toHaveLength(4);
    expect(snapshot.users.map(({ email, id }) => ({ email, id }))).toEqual([
      { email: "a@example.com", id: "PUSER1" },
      { email: "b@example.com", id: "PUSER2" },
    ]);
    expect(snapshot.teams).toEqual([{ id: "PTEAM1", name: "Platform" }]);
    expect(snapshot.memberships).toEqual([
      { role: "responder", teamId: "PTEAM1", userId: "PUSER2" },
    ]);
    expect(snapshot.capturedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/u);
  });

  it("fails closed on provider errors and request-budget exhaustion", async () => {
    const denied = new PagerDutyTeamReader({
      fetchImpl: vi.fn(async () => json({ error: "secret detail" }, 403)),
      token: "test-token",
    });
    await expect(denied.snapshot([])).rejects.toEqual(
      new PagerDutyTeamRequestError(403),
    );

    const limited = new PagerDutyTeamReader({
      fetchImpl: vi.fn(async () =>
        json({ limit: 1, more: true, offset: 0, users: [] }),
      ),
      maxRequests: 1,
      token: "test-token",
    });
    await expect(limited.snapshot([])).rejects.toThrow(
      "pagerduty_team_sync_request_limit_exceeded",
    );
  });

  it("rejects duplicate team IDs before any provider request", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const reader = new PagerDutyTeamReader({ fetchImpl, token: "test-token" });
    await expect(reader.snapshot(["PTEAM1", "PTEAM1"])).rejects.toThrow(
      "pagerduty_team_ids_duplicate",
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects a provider page that does not match the requested offset", async () => {
    const reader = new PagerDutyTeamReader({
      fetchImpl: vi.fn(async () =>
        json({ limit: 100, more: false, offset: 10, users: [] }),
      ),
      token: "test-token",
    });
    await expect(reader.snapshot([])).rejects.toThrow(
      "pagerduty_team_sync_invalid_page",
    );
  });

  it("puts one exact membership role and reads it back from the pinned team", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(
        json({
          limit: 100,
          members: [{ role: "responder", user: { id: "PUSER1" } }],
          more: false,
          offset: 0,
        }),
      );
    const client = new PagerDutyTeamReader({ fetchImpl, token: "write-token" });

    await client.putTeamMembership("PTEAM1", "PUSER1", "responder");
    await expect(client.getTeamMembership("PTEAM1", "PUSER1")).resolves.toEqual(
      {
        role: "responder",
      },
    );

    const [putInput, putInit] = fetchImpl.mock.calls[0] ?? [];
    expect(requestUrl(requireRequestInput(putInput))).toBe(
      "https://api.pagerduty.com/teams/PTEAM1/users/PUSER1",
    );
    expect(putInit?.body).toBe(JSON.stringify({ role: "responder" }));
    const putHeaders = new Headers(putInit?.headers);
    expect(putHeaders.get("accept")).toBe(
      "application/vnd.pagerduty+json;version=2",
    );
    expect(putHeaders.get("authorization")).toBe("Token token=write-token");
    expect(putHeaders.get("content-type")).toBe("application/json");
    const [readInput] = fetchImpl.mock.calls[1] ?? [];
    expect(requestUrl(requireRequestInput(readInput))).toBe(
      "https://api.pagerduty.com/teams/PTEAM1/members?limit=100&offset=0",
    );
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("requires the exact mutation status and never exposes a delete request", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json({}));
    const client = new PagerDutyTeamReader({ fetchImpl, token: "write-token" });
    await expect(
      client.putTeamMembership("PTEAM1", "PUSER1", "responder"),
    ).rejects.toEqual(new PagerDutyTeamUnexpectedMutationStatusError(200));
    expect(fetchImpl.mock.calls[0]?.[1]?.method).toBe("PUT");
  });
});
