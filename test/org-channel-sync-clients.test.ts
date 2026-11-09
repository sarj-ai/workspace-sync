import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";

import {
  GoogleGroupMembershipWriter,
  GoogleGroupsClient,
} from "../src/org-sync/google-groups-client.ts";
import { OrgChannelSlackClient } from "../src/org-sync/org-channel-slack-client.ts";
import { SlackWriteOutcomeUnknownError } from "../src/org-sync/slack-api-transport.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";
import { isString } from "./support/value-guards.ts";

function requestUrl(input: RequestInfo | URL): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

function privilegedMemberReadback(target: {
  deleted: boolean;
  memberEmail: string;
  memberId: string;
}): Response {
  return target.deleted
    ? new Response(null, { status: 404 })
    : Response.json({
        email: target.memberEmail,
        id: target.memberId,
        role: "OWNER",
        type: "USER",
      });
}

function slackUserGroupResponse(
  users: readonly string[],
  channelIds: readonly string[] = [],
): Response {
  return Response.json({
    ok: true,
    usergroups: [
      {
        "date_delete": 0,
        handle: "group-marketing",
        id: "SMARKETING",
        name: "Marketing",
        prefs: { channels: channelIds, groups: [] },
        users,
      },
    ],
  });
}

function slackReadFetch(input: RequestInfo | URL): Response {
  const url = requestUrl(input);
  switch (url.pathname.split("/").pop() ?? "") {
    case "auth.test": {
      return Response.json(
        { ok: true, "team_id": "TWORKSPACE", "user_id": "UACTOR" },
        {
          headers: {
            "x-oauth-scopes":
              "users:read.email,groups:read,users:read,channels:read,usergroups:read",
          },
        },
      );
    }
    case "users.list": {
      return Response.json({
        members: [
          {
            deleted: false,
            id: "U1",
            "is_admin": false,
            "is_app_user": false,
            "is_bot": false,
            "is_owner": false,
            "is_primary_owner": false,
            "is_restricted": false,
            "is_ultra_restricted": false,
            profile: { email: "person@company.test" },
          },
        ],
        ok: true,
        "response_metadata": { "next_cursor": "" },
      });
    }
    case "conversations.info": {
      const id = url.searchParams.get("channel") ?? "";
      return Response.json({
        channel: {
          id,
          "is_archived": false,
          "is_private": id === "CPRIVATE",
          name: id === "CPRIVATE" ? "marketing" : "asks-marketing",
        },
        ok: true,
      });
    }
    case "conversations.list": {
      return Response.json({
        channels: [
          {
            id: "CPRIVATE",
            "is_archived": false,
            "is_private": true,
            name: "marketing",
          },
          {
            id: "CASKS",
            "is_archived": false,
            "is_private": false,
            name: "asks-marketing",
          },
        ],
        ok: true,
        "response_metadata": { "next_cursor": "" },
      });
    }
    case "conversations.members": {
      return url.searchParams.has("cursor")
        ? Response.json({ members: ["U2"], ok: true })
        : Response.json({
            members: ["U1"],
            ok: true,
            "response_metadata": { "next_cursor": "next" },
          });
    }
    case "usergroups.list": {
      return Response.json({
        ok: true,
        usergroups: [
          {
            "date_delete": 0,
            handle: "group-marketing",
            id: "SMARKETING",
            name: "group-marketing",
            prefs: { channels: ["CASKS"], groups: ["CPRIVATE"] },
            users: ["U1"],
          },
        ],
      });
    }
    default: {
      return Response.json({ error: "unexpected_method", ok: false });
    }
  }
}

function slackReadFetchWithExtraAssociation(
  input: RequestInfo | URL,
): Response {
  const url = requestUrl(input);
  if (url.pathname.endsWith("/conversations.list")) {
    return Response.json({
      channels: [
        {
          id: "CPRIVATE",
          "is_archived": false,
          "is_private": true,
          name: "marketing",
        },
        {
          id: "CASKS",
          "is_archived": false,
          "is_private": false,
          name: "asks-marketing",
        },
        {
          id: "CEXTRA",
          "is_archived": false,
          "is_private": true,
          name: "legacy-marketing-private",
        },
        {
          id: "CIGNORED",
          "is_archived": false,
          "is_private": true,
          name: "unmanaged-private",
        },
      ],
      ok: true,
      "response_metadata": { "next_cursor": "" },
    });
  }
  if (url.pathname.endsWith("/conversations.info")) {
    const id = url.searchParams.get("channel") ?? "";
    let isPrivate = true;
    let name = "unknown";
    switch (id) {
      case "CASKS": {
        isPrivate = false;
        name = "asks-marketing";
        break;
      }
      case "CEXTRA": {
        name = "legacy-marketing-private";
        break;
      }
      case "CPRIVATE": {
        name = "marketing";
        break;
      }
    }
    return Response.json({
      channel: {
        id,
        "is_archived": false,
        "is_private": isPrivate,
        name,
      },
      ok: true,
    });
  }
  if (url.pathname.endsWith("/usergroups.list")) {
    return Response.json({
      ok: true,
      usergroups: [
        {
          "date_delete": 0,
          handle: "group-marketing",
          id: "SMARKETING",
          name: "Marketing",
          prefs: { channels: ["CASKS"], groups: ["CPRIVATE", "CEXTRA"] },
          users: ["U1"],
        },
        {
          "date_delete": 0,
          handle: "unmanaged-group",
          id: "SUNMANAGED",
          name: "Unmanaged",
          prefs: { channels: [], groups: ["CIGNORED"] },
          users: ["U1"],
        },
      ],
    });
  }
  return slackReadFetch(input);
}

interface GoogleFetchState {
  delegatedScope: string;
  requests: {
    authorization: null | string;
    url: URL;
    userProject: null | string;
  }[];
}

function googleGroupsFetch(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  state: GoogleFetchState,
): Response {
  const url = requestUrl(input);
  if (url.hostname === "oauth2.googleapis.com")
    return googleOauthResponse(init, state);
  const headers = new Headers(init?.headers);
  state.requests.push({
    authorization: headers.get("authorization"),
    url,
    userProject: headers.get("x-goog-user-project"),
  });
  if (url.pathname.endsWith("/groups") && url.searchParams.has("customer")) {
    return Response.json({
      groups: [
        { email: "team-marketing@company.test", id: "immutable-group-id" },
      ],
    });
  }
  if (!url.pathname.endsWith("/members")) {
    return Response.json({
      email: "team-marketing@company.test",
      id: "immutable-group-id",
    });
  }
  return url.searchParams.has("pageToken")
    ? Response.json({
        members: [
          {
            email: "nested@company.test",
            id: "group-2",
            role: "MEMBER",
            status: "ACTIVE",
            type: "GROUP",
          },
        ],
      })
    : Response.json({
        members: [
          {
            email: "owner@company.test",
            id: "g1",
            role: "OWNER",
            status: "ACTIVE",
            type: "USER",
          },
        ],
        nextPageToken: "next",
      });
}

function googleOauthResponse(
  init: RequestInit | undefined,
  state: GoogleFetchState,
): Response {
  const body =
    init?.body instanceof URLSearchParams ? init.body.toString() : "";
  const assertion = new URLSearchParams(body).get("assertion") ?? "";
  const payload = decodeJwt(assertion);
  state.delegatedScope = isString(payload.scope) ? payload.scope : "";
  return Response.json({ "access_token": "groups-token", "expires_in": 3600 });
}

interface GoogleMembershipWriterFetchState {
  authorization: null | string;
  delegatedScope: string;
  memberReads: number;
  methods: string[];
  userProject: null | string;
}

function googleMembershipWriterHappyFetch(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  state: GoogleMembershipWriterFetchState,
  target: {
    groupEmail: string;
    groupId: string;
    memberEmail: string;
    memberId: string;
  },
): Response {
  const url = requestUrl(input);
  if (url.hostname === "oauth2.googleapis.com") {
    const body =
      init?.body instanceof URLSearchParams ? init.body.toString() : "";
    const assertion = new URLSearchParams(body).get("assertion") ?? "";
    const payload = decodeJwt(assertion);
    state.delegatedScope = isString(payload.scope) ? payload.scope : "";
    return Response.json({
      "access_token": "groups-write-token",
      "expires_in": 3600,
    });
  }
  state.methods.push(init?.method ?? "GET");
  state.authorization = new Headers(init?.headers).get("authorization");
  state.userProject = new Headers(init?.headers).get("x-goog-user-project");
  if (url.pathname.endsWith("/immutable-group-id")) {
    return Response.json({ email: target.groupEmail, id: target.groupId });
  }
  if (init?.method === "DELETE") return new Response(null, { status: 204 });
  state.memberReads++;
  if (state.methods.includes("DELETE"))
    return new Response(null, { status: 404 });
  return Response.json({
    email: target.memberEmail,
    id: target.memberId,
    role: "MEMBER",
    status: "SUSPENDED",
    type: "USER",
  });
}

describe("Google Groups read-only client", () => {
  it("can preserve the provider primary email for a pinned contractor inventory snapshot", async () => {
    const state: GoogleFetchState = { delegatedScope: "", requests: [] };
    const client = new GoogleGroupsClient({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(googleOauthResponse(init, state));
        }
        if (url.pathname.endsWith("/members"))
          return Promise.resolve(Response.json({ members: [] }));
        return Promise.resolve(
          Response.json({
            email: "team-eng-contract@company.test",
            id: "contractor-group-test",
          }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    const canonical = await client.listGroups(
      ["team-eng-contract@company.test"],
      "canonical-run",
    );
    const pinned = await client.listGroups(
      ["team-eng-contract@company.test"],
      "pinned-run",
      undefined,
      false,
      true,
    );

    expect(canonical[0]?.email).toBe("team-contractors@company.test");
    expect(pinned[0]?.email).toBe("team-eng-contract@company.test");
    expect(pinned[0]?.id).toBe(canonical[0]?.id);
  });

  it("loads nested Google groups only when recursive expansion is requested", async () => {
    const state: GoogleFetchState = { delegatedScope: "", requests: [] };
    const client = new GoogleGroupsClient({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(googleOauthResponse(init, state));
        }
        const headers = new Headers(init?.headers);
        state.requests.push({
          authorization: headers.get("authorization"),
          url,
          userProject: headers.get("x-goog-user-project"),
        });
        const parts = url.pathname.split("/");
        if (url.pathname.endsWith("/members")) {
          const groupId = parts.at(-2);
          return Promise.resolve(
            groupId === "parent-id"
              ? Response.json({
                  members: [
                    {
                      email: "nested@company.test",
                      id: "nested-membership",
                      role: "MEMBER",
                      status: "ACTIVE",
                      type: "GROUP",
                    },
                  ],
                })
              : Response.json({
                  members: [
                    {
                      email: "person@company.test",
                      id: "person-id",
                      role: "MEMBER",
                      status: "ACTIVE",
                      type: "USER",
                    },
                  ],
                }),
          );
        }
        const groupEmail = decodeURIComponent(parts.at(-1) ?? "");
        return Promise.resolve(
          Response.json({
            email: groupEmail,
            id:
              groupEmail === "team-eng@company.test"
                ? "parent-id"
                : "nested-id",
          }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    const shallowGroups = await client.listGroups(
      ["team-eng@company.test"],
      "shallow-run",
    );
    const groups = await client.listGroups(
      ["team-eng@company.test"],
      "run-id",
      undefined,
      true,
    );

    expect(shallowGroups.map((group) => group.email)).toEqual([
      "team-eng@company.test",
    ]);
    expect(groups.map((group) => group.email)).toEqual([
      "team-eng@company.test",
      "nested@company.test",
    ]);
    expect(groups[1]?.members).toContainEqual(
      expect.objectContaining({ email: "person@company.test", type: "USER" }),
    );
  });

  it("fails closed on inactive nested groups and recursive breadth overflow", async () => {
    const privateKey = await rsaPrivateKeyFixture();
    const clientForMembers = (members: unknown[]) =>
      new GoogleGroupsClient({
        adminSubject: "root-admin@company.test",
        fetchImpl: (input, init) => {
          const url = requestUrl(input);
          if (url.hostname === "oauth2.googleapis.com") {
            return Promise.resolve(
              googleOauthResponse(init, { delegatedScope: "", requests: [] }),
            );
          }
          if (url.pathname.endsWith("/members")) {
            return Promise.resolve(Response.json({ members }));
          }
          const email = decodeURIComponent(
            url.pathname.split("/").at(-1) ?? "",
          );
          return Promise.resolve(Response.json({ email, id: "parent-id" }));
        },
        privateKey,
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: () => Promise.resolve(),
        userProject: "workspace-sync-test",
      });
    const nestedMember = (index: number, status: "ACTIVE" | "SUSPENDED") => ({
      email: `nested-${String(index)}@company.test`,
      id: `nested-${String(index)}`,
      role: "MEMBER",
      status,
      type: "GROUP",
    });

    await expect(
      clientForMembers([nestedMember(1, "SUSPENDED")]).listGroups(
        ["team-eng@company.test"],
        "inactive-run",
        undefined,
        true,
      ),
    ).rejects.toThrow("is SUSPENDED");
    await expect(
      clientForMembers(
        Array.from({ length: 50 }, (_, index) => nestedMember(index, "ACTIVE")),
      ).listGroups(["team-eng@company.test"], "breadth-run", undefined, true),
    ).rejects.toThrow("Google group expansion exceeded 50 groups");
  });

  it("rejects a derived team address that resolves through an alias to another group", async () => {
    const state: GoogleFetchState = { delegatedScope: "", requests: [] };
    let membershipReads = 0;
    const client = new GoogleGroupsClient({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(googleOauthResponse(init, state));
        }
        if (url.pathname.endsWith("/members")) membershipReads++;
        return Promise.resolve(
          Response.json({
            email: "everyone@company.test",
            id: "unrelated-group-id",
          }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.listGroups(["team-eng@company.test"], "run-id"),
    ).rejects.toThrow("resolved to a different primary address");
    expect(membershipReads).toBe(0);
  });

  it("authenticates with delegated group-read scope and exhausts member pagination", async () => {
    const state: GoogleFetchState = { delegatedScope: "", requests: [] };
    const client = new GoogleGroupsClient({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) =>
        Promise.resolve(googleGroupsFetch(input, init, state)),
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    const groups = await client.listGroups(
      ["team-marketing@company.test"],
      "run-id",
    );
    const inventory = await client.listAllGroups("run-id");
    expect(groups).toEqual([
      {
        email: "team-marketing@company.test",
        id: "immutable-group-id",
        members: [
          expect.objectContaining({
            email: "owner@company.test",
            role: "OWNER",
            type: "USER",
          }),
          expect.objectContaining({
            email: "nested@company.test",
            type: "GROUP",
          }),
        ],
      },
    ]);
    expect(inventory).toEqual([
      { email: "team-marketing@company.test", id: "immutable-group-id" },
    ]);
    expect(state.requests).toHaveLength(4);
    expect(state.delegatedScope).toBe(
      "https://www.googleapis.com/auth/admin.directory.group.readonly",
    );
    expect(
      state.requests.every(
        (request) => request.authorization === "Bearer groups-token",
      ),
    ).toBe(true);
    expect(
      state.requests.every(
        (request) => request.userProject === "workspace-sync-test",
      ),
    ).toBe(true);
  });
});

async function concurrentGroupsClient(read: (url: URL) => Promise<Response>) {
  return new GoogleGroupsClient({
    adminSubject: "root-admin@company.test",
    fetchImpl: async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com")
        return Response.json({
          "access_token": "test-groups-token",
          "expires_in": 3600,
        });
      return read(url);
    },
    privateKey: await rsaPrivateKeyFixture(),
    serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
    sleep: async () => undefined,
    userProject: "workspace-sync-test",
  });
}

function groupIdentityResponse(url: URL) {
  const email = decodeURIComponent(url.pathname.split("/").at(-1) ?? "");
  return Response.json({ email, id: email.split("@", 1)[0] });
}

describe("Google direct-group bounded snapshot reads", () => {
  it("bounds both phases at four, resolves all identities first, and preserves input order", async () => {
    const pending: { url: URL; resolve: (value: Response) => void }[] = [];
    let active = 0;
    let maximum = 0;
    const client = await concurrentGroupsClient(async (url) => {
      active++;
      maximum = Math.max(maximum, active);
      const { promise, resolve } = Promise.withResolvers<Response>();
      pending.push({ url, resolve });
      try {
        return await promise;
      } finally {
        active--;
      }
    });
    const keys = Array.from(
      { length: 7 },
      (_, index) => `group-${String(index)}@company.test`,
    );
    const result = client.listGroups(keys, "bounded");
    await vi.waitFor(() => expect(pending).toHaveLength(4));
    for (const item of [...pending].toReversed())
      item.resolve(groupIdentityResponse(item.url));
    await vi.waitFor(() => expect(pending).toHaveLength(7));
    expect(pending.every(({ url }) => !url.pathname.endsWith("/members"))).toBe(
      true,
    );
    for (const item of pending.slice(4).toReversed())
      item.resolve(groupIdentityResponse(item.url));
    await vi.waitFor(() => expect(pending).toHaveLength(11));
    for (const item of pending.slice(7).toReversed())
      item.resolve(Response.json({ members: [] }));
    await vi.waitFor(() => expect(pending).toHaveLength(14));
    for (const item of pending.slice(11).toReversed())
      item.resolve(Response.json({ members: [] }));
    const groups = await result;
    expect(groups.map(({ email }) => email)).toEqual(keys);
    expect(maximum).toBe(4);
    expect(active).toBe(0);
  });

  it("rejects duplicate immutable IDs before any membership request", async () => {
    const memberRead = vi.fn();
    const client = await concurrentGroupsClient(async (url) => {
      if (url.pathname.endsWith("/members")) memberRead();
      const email = decodeURIComponent(url.pathname.split("/").at(-1) ?? "");
      return Response.json({ email, id: "same-immutable-id" });
    });
    await expect(
      client.listGroups(["one@company.test", "two@company.test"], "duplicates"),
    ).rejects.toThrow("Multiple configured Google groups");
    expect(memberRead).not.toHaveBeenCalled();
  });

  it.each(["identity", "members"] as const)(
    "drains an in-flight %s batch before failing and starts no later batch",
    async (phase) => {
      const pending: { resolve: (value: Response) => void; url: URL }[] = [];
      let calls = 0;
      const client = await concurrentGroupsClient(async (url) => {
        const isMember = url.pathname.endsWith("/members");
        if (phase === "members" && !isMember) return groupIdentityResponse(url);
        calls++;
        if (calls === 1) return new Response(null, { status: 403 });
        const { promise, resolve } = Promise.withResolvers<Response>();
        pending.push({ resolve, url });
        return promise;
      });
      let finished = false;
      const outcome = (async () => {
        try {
          await client.listGroups(
            Array.from(
              { length: 5 },
              (_, index) => `group-${String(index)}@company.test`,
            ),
            "failed-batch",
          );
          return null;
        } catch (error: unknown) {
          return error;
        } finally {
          finished = true;
        }
      })();
      await vi.waitFor(() => expect(pending).toHaveLength(3));
      expect(finished).toBe(false);
      for (const item of pending)
        item.resolve(
          phase === "members"
            ? Response.json({ members: [] })
            : groupIdentityResponse(item.url),
        );
      await expect(outcome).resolves.toBeInstanceOf(Error);
      expect(calls).toBe(4);
    },
  );

  it.each(["repeated-token", "invalid-page"] as const)(
    "rejects incomplete member pagination: %s",
    async (failure) => {
      const client = await concurrentGroupsClient(async (url) => {
        if (!url.pathname.endsWith("/members"))
          return groupIdentityResponse(url);
        if (url.searchParams.has("pageToken") && failure === "invalid-page")
          return Response.json({ members: [{ id: "incomplete" }] });
        return Response.json({ members: [], nextPageToken: "again" });
      });
      await expect(
        client.listGroups(["one@company.test", "two@company.test"], "pages"),
      ).rejects.toThrow();
    },
  );

  it("carries the same absolute deadline into membership reads without starting requests after expiry", async () => {
    const deadline = Date.now() + 60_000;
    const clock = vi.spyOn(Date, "now");
    const memberRead = vi.fn();
    try {
      const client = await concurrentGroupsClient(async (url) => {
        if (url.pathname.endsWith("/members")) memberRead();
        clock.mockReturnValue(deadline);
        return groupIdentityResponse(url);
      });
      await expect(
        client.listGroups(["one@company.test"], "deadline", deadline),
      ).rejects.toThrow("deadline exceeded");
      expect(memberRead).not.toHaveBeenCalled();
    } finally {
      clock.mockRestore();
    }
  });
});

describe("Google Groups direct-membership writer", () => {
  const target = {
    groupEmail: "team-platform@company.test",
    groupId: "immutable-group-id",
    memberEmail: "inactive@company.test",
    memberId: "immutable-member-id",
  } as const;

  it.each(["MANAGER", "OWNER"] as const)(
    "removes an inactive %s only through fresh signed parent authority",
    async (role) => {
      let deleted = false;
      const calls: string[] = [];
      const client = new GoogleGroupMembershipWriter({
        adminSubject: "root-admin@company.test",
        fetchImpl: async (input, init) => {
          const url = requestUrl(input);
          if (url.hostname === "oauth2.googleapis.com")
            return Response.json({
              "access_token": "token",
              "expires_in": 3600,
            });
          if (url.pathname.endsWith("/immutable-group-id"))
            return Response.json({
              email: target.groupEmail,
              id: target.groupId,
            });
          if (init?.method === "DELETE") {
            calls.push("DELETE");
            deleted = true;
            return new Response(null, { status: 204 });
          }
          return deleted
            ? new Response(null, { status: 404 })
            : Response.json({
                id: target.memberId,
                email: target.memberEmail,
                role,
                type: "USER",
              });
        },
        privateKey: await rsaPrivateKeyFixture(),
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: async () => undefined,
        userProject: "workspace-sync-test",
      });
      await expect(
        client.removeDirectMember({ ...target, role }, "run-id"),
      ).rejects.toThrow("requires signed parent authority");
      expect(calls).toEqual([]);
      await expect(
        client.removeDirectMember(
          { ...target, role },
          "run-id",
          undefined,
          undefined,
          {
            assertWriteAuthority: async () => {
              calls.push("write-authority");
            },
            assertFinalSourceAuthority: async () => {
              calls.push("source-authority");
            },
            assertFreshPlan: () => {
              calls.push("fresh-plan");
            },
          },
        ),
      ).resolves.toEqual({ wrote: true });
      expect(calls).toEqual([
        "write-authority",
        "source-authority",
        "fresh-plan",
        "DELETE",
      ]);
    },
  );

  it.each(["admin-promotion", "reactivation"] as const)(
    "rejects Google %s during the last provider target read",
    async (drift) => {
      const authority = { isAdmin: false, suspended: true };
      const methods: string[] = [];
      let memberReads = 0;
      const started = vi.fn<() => void>();
      const finalSource = vi.fn(async () => {
        if (authority.isAdmin || !authority.suspended)
          throw new Error("fresh Google authority denied");
      });
      const client = new GoogleGroupMembershipWriter({
        adminSubject: "root-admin@company.test",
        fetchImpl: async (input, init) => {
          const url = requestUrl(input);
          if (url.hostname === "oauth2.googleapis.com")
            return Response.json({
              "access_token": "token",
              "expires_in": 3600,
            });
          methods.push(init?.method ?? "GET");
          if (url.pathname.endsWith("/immutable-group-id"))
            return Response.json({
              email: target.groupEmail,
              id: target.groupId,
            });
          memberReads += 1;
          if (memberReads === 2) {
            authority.isAdmin = drift === "admin-promotion";
            authority.suspended = drift !== "reactivation";
          }
          return Response.json({
            email: target.memberEmail,
            id: target.memberId,
            role: "MEMBER",
            type: "USER",
          });
        },
        privateKey: await rsaPrivateKeyFixture(),
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: () => Promise.resolve(),
        userProject: "workspace-sync-test",
      });
      await expect(
        client.removeDirectMember(target, "run-id", undefined, started, {
          assertWriteAuthority: async () => undefined,
          assertFinalSourceAuthority: finalSource,
          assertFreshPlan: () => undefined,
        }),
      ).rejects.toThrow("fresh Google authority denied");
      expect(methods).toEqual(["GET", "GET", "GET", "GET"]);
      expect(finalSource).toHaveBeenCalledOnce();
      expect(started).not.toHaveBeenCalled();
    },
  );

  it("deletes only the exact direct USER/MEMBER and verifies immutable-ID absence", async () => {
    const state: GoogleMembershipWriterFetchState = {
      authorization: null,
      delegatedScope: "",
      memberReads: 0,
      methods: [],
      userProject: null,
    };
    const onMutationStart = vi.fn<() => void>();
    const client = new GoogleGroupMembershipWriter({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) =>
        Promise.resolve(
          googleMembershipWriterHappyFetch(input, init, state, target),
        ),
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.removeDirectMember(target, "run-id", undefined, onMutationStart),
    ).resolves.toEqual({ wrote: true });
    expect(state.methods).toEqual(["GET", "GET", "DELETE", "GET", "GET"]);
    expect(state.authorization).toBe("Bearer groups-write-token");
    expect(state.userProject).toBe("workspace-sync-test");
    expect(onMutationStart).toHaveBeenCalledOnce();
    expect(state.delegatedScope.split(" ")).toEqual([
      "https://www.googleapis.com/auth/admin.directory.group.readonly",
      "https://www.googleapis.com/auth/admin.directory.group.member",
    ]);
  });

  it.each([
    {
      group: { email: "aliased@company.test", id: target.groupId },
      member: null,
      name: "group primary-email drift",
    },
    {
      group: { email: target.groupEmail, id: "different-group-id" },
      member: null,
      name: "group immutable-ID drift",
    },
    {
      group: { email: target.groupEmail, id: target.groupId },
      member: {
        email: target.memberEmail,
        id: "different-member-id",
        role: "MEMBER",
        type: "USER",
      },
      name: "member immutable-ID drift",
    },
    {
      group: { email: target.groupEmail, id: target.groupId },
      member: {
        email: target.memberEmail,
        id: target.memberId,
        role: "OWNER",
        type: "USER",
      },
      name: "owner role",
    },
    {
      group: { email: target.groupEmail, id: target.groupId },
      member: {
        email: target.memberEmail,
        id: target.memberId,
        role: "MEMBER",
        type: "GROUP",
      },
      name: "nested group",
    },
    {
      group: { email: target.groupEmail, id: target.groupId },
      member: {
        email: "other@company.test",
        id: target.memberId,
        role: "MEMBER",
        type: "USER",
      },
      name: "member email drift",
    },
  ])("fails closed without a DELETE for $name", async ({ group, member }) => {
    let deletes = 0;
    const onMutationStart = vi.fn<() => void>();
    const client = new GoogleGroupMembershipWriter({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(
            Response.json({ "access_token": "token", "expires_in": 3600 }),
          );
        }
        if (init?.method === "DELETE") deletes++;
        if (url.pathname.endsWith("/immutable-group-id"))
          return Promise.resolve(Response.json(group));
        if (member === null)
          return Promise.resolve(new Response(null, { status: 404 }));
        return Promise.resolve(Response.json(member));
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.removeDirectMember(target, "run-id", undefined, onMutationStart),
    ).rejects.toThrow(/changed|absent/);
    expect(deletes).toBe(0);
    expect(onMutationStart).not.toHaveBeenCalled();
  });

  it.each([
    { mode: "legacy", attempts: 3, failure: "network" },
    { mode: "parent", attempts: 1, failure: "network" },
    { mode: "parent", attempts: 1, failure: "503" },
  ])(
    "accepts ambiguous $mode $failure DELETE only after original members.get returns 404",
    async ({ mode, attempts, failure }) => {
      let deleteAttempts = 0;
      const memberPaths: string[] = [];
      const ambiguousDelete = () =>
        failure === "network"
          ? Promise.reject(new Error("ambiguous network failure"))
          : Promise.resolve(new Response(null, { status: 503 }));
      const onMutationStart = vi.fn<() => void>();
      const client = new GoogleGroupMembershipWriter({
        adminSubject: "root-admin@company.test",
        fetchImpl: (input, init) => {
          const url = requestUrl(input);
          if (url.hostname === "oauth2.googleapis.com") {
            return Promise.resolve(
              Response.json({ "access_token": "token", "expires_in": 3600 }),
            );
          }
          if (url.pathname.endsWith("/immutable-group-id")) {
            return Promise.resolve(
              Response.json({ email: target.groupEmail, id: target.groupId }),
            );
          }
          memberPaths.push(url.pathname);
          if (init?.method === "DELETE") {
            deleteAttempts++;
            return ambiguousDelete();
          }
          return Promise.resolve(
            deleteAttempts === 0
              ? Response.json({
                  email: target.memberEmail,
                  id: target.memberId,
                  role: "MEMBER",
                  type: "USER",
                })
              : new Response(null, { status: 404 }),
          );
        },
        privateKey: await rsaPrivateKeyFixture(),
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: () => Promise.resolve(),
        userProject: "workspace-sync-test",
      });

      await expect(
        client.removeDirectMember(
          target,
          "run-id",
          undefined,
          onMutationStart,
          mode === "parent"
            ? {
                assertWriteAuthority: async () => undefined,
                assertFreshPlan: () => undefined,
                assertFinalSourceAuthority: async () => undefined,
              }
            : undefined,
        ),
      ).resolves.toEqual({ wrote: true });
      expect(deleteAttempts).toBe(attempts);
      expect(memberPaths).toEqual(
        Array.from(
          { length: attempts + (mode === "parent" ? 3 : 2) },
          () =>
            `/admin/directory/v1/groups/${target.groupId}/members/${target.memberId}`,
        ),
      );
      expect(onMutationStart).toHaveBeenCalledOnce();
    },
  );

  it.each(["legacy", "parent"] as const)(
    "preserves the ambiguous %s DELETE failure when immutable-ID readback still finds the member",
    async (mode) => {
      const onMutationStart = vi.fn<() => void>();
      const client = new GoogleGroupMembershipWriter({
        adminSubject: "root-admin@company.test",
        fetchImpl: (input, init) => {
          const url = requestUrl(input);
          if (url.hostname === "oauth2.googleapis.com") {
            return Promise.resolve(
              Response.json({ "access_token": "token", "expires_in": 3600 }),
            );
          }
          if (url.pathname.endsWith("/immutable-group-id")) {
            return Promise.resolve(
              Response.json({ email: target.groupEmail, id: target.groupId }),
            );
          }
          if (init?.method === "DELETE")
            return Promise.reject(new Error("ambiguous network failure"));
          return Promise.resolve(
            Response.json({
              email: target.memberEmail,
              id: target.memberId,
              role: "MEMBER",
              type: "USER",
            }),
          );
        },
        privateKey: await rsaPrivateKeyFixture(),
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: () => Promise.resolve(),
        userProject: "workspace-sync-test",
      });

      await expect(
        client.removeDirectMember(
          target,
          "run-id",
          undefined,
          onMutationStart,
          mode === "parent"
            ? {
                assertWriteAuthority: async () => undefined,
                assertFreshPlan: () => undefined,
                assertFinalSourceAuthority: async () => undefined,
              }
            : undefined,
        ),
      ).rejects.toThrow("google.directory.members.delete network failure");
      expect(onMutationStart).toHaveBeenCalledOnce();
    },
  );

  it.each(["authority", "expiry", "missing-expiry"] as const)(
    "denies parent %s after awaited target reads without starting a mutation",
    async (failure) => {
      const state: GoogleMembershipWriterFetchState = {
        authorization: null,
        delegatedScope: "",
        memberReads: 0,
        methods: [],
        userProject: null,
      };
      let expired = false;
      const guardReadStates: string[][] = [];
      const parent = {
        assertFinalSourceAuthority: vi.fn(async () => undefined),
        assertWriteAuthority: vi.fn(async () => {
          guardReadStates.push([...state.methods]);
          await Promise.resolve();
          expired = true;
          if (failure === "authority")
            throw new Error("parent authority denied");
        }),
        assertFreshPlan: vi.fn(() => {
          if (expired) throw new Error("parent expired");
        }),
      };
      if (failure === "missing-expiry")
        Reflect.deleteProperty(parent, "assertFreshPlan");
      const started = vi.fn<() => void>();
      const client = new GoogleGroupMembershipWriter({
        adminSubject: "root-admin@company.test",
        fetchImpl: async (input, init) => {
          await Promise.resolve();
          return googleMembershipWriterHappyFetch(input, init, state, target);
        },
        privateKey: await rsaPrivateKeyFixture(),
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: () => Promise.resolve(),
        userProject: "workspace-sync-test",
      });
      await expect(
        client.removeDirectMember(target, "run-id", undefined, started, parent),
      ).rejects.toThrow();
      expect(state.methods).toEqual(
        Array.from({ length: failure === "authority" ? 2 : 4 }, () => "GET"),
      );
      expect(guardReadStates).toEqual([["GET", "GET"]]);
      expect(parent.assertWriteAuthority).toHaveBeenCalledOnce();
      expect(started).not.toHaveBeenCalled();
    },
  );

  it.each(["member-promotion", "group-replacement"] as const)(
    "rejects parent-guard %s before starting DELETE",
    async (drift) => {
      let authorityChecked = false;
      const methods: string[] = [];
      const started = vi.fn<() => void>();
      const freshPlan = vi.fn<() => void>();
      const client = new GoogleGroupMembershipWriter({
        adminSubject: "root-admin@company.test",
        fetchImpl: async (input, init) => {
          await Promise.resolve();
          const url = requestUrl(input);
          if (url.hostname === "oauth2.googleapis.com")
            return Response.json({
              "access_token": "token",
              "expires_in": 3600,
            });
          methods.push(init?.method ?? "GET");
          if (url.pathname.endsWith("/immutable-group-id"))
            return Response.json({
              email: target.groupEmail,
              id:
                authorityChecked && drift === "group-replacement"
                  ? "replacement-group"
                  : target.groupId,
            });
          return Response.json({
            email: target.memberEmail,
            id: target.memberId,
            role: authorityChecked ? "OWNER" : "MEMBER",
            type: "USER",
          });
        },
        privateKey: await rsaPrivateKeyFixture(),
        serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
        sleep: () => Promise.resolve(),
        userProject: "workspace-sync-test",
      });
      await expect(
        client.removeDirectMember(target, "run-id", undefined, started, {
          assertWriteAuthority: async () => {
            await Promise.resolve();
            authorityChecked = true;
          },
          assertFreshPlan: freshPlan,
          assertFinalSourceAuthority: async () => undefined,
        }),
      ).rejects.toThrow("changed before direct-membership removal");
      expect(methods).toEqual(
        Array.from(
          { length: drift === "group-replacement" ? 3 : 4 },
          () => "GET",
        ),
      );
      expect(started).not.toHaveBeenCalled();
      expect(freshPlan).not.toHaveBeenCalled();
    },
  );
});

describe("Google Groups privileged-membership writer", () => {
  const target = {
    groupEmail: "team-platform@company.test",
    groupId: "immutable-group-id",
    memberEmail: "inactive@company.test",
    memberId: "immutable-member-id",
    role: "OWNER" as const,
  };

  it("removes the exact owner only after proving two direct owners and verifies absence", async () => {
    const methods: string[] = [];
    let deleted = false;
    const client = new GoogleGroupMembershipWriter({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(
            Response.json({ "access_token": "token", "expires_in": 3600 }),
          );
        }
        methods.push(init?.method ?? "GET");
        if (url.pathname.endsWith("/immutable-group-id")) {
          return Promise.resolve(
            Response.json({ email: target.groupEmail, id: target.groupId }),
          );
        }
        if (url.searchParams.get("roles") === "OWNER") {
          return Promise.resolve(
            Response.json({
              members: [
                {
                  email: target.memberEmail,
                  id: target.memberId,
                  role: "OWNER",
                  type: "USER",
                },
                {
                  email: "other@company.test",
                  id: "other-owner-id",
                  role: "OWNER",
                  type: "USER",
                },
              ],
            }),
          );
        }
        if (init?.method === "DELETE") {
          deleted = true;
          return Promise.resolve(new Response(null, { status: 204 }));
        }
        return Promise.resolve(
          privilegedMemberReadback({ ...target, deleted }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.removePrivilegedDirectMember(target, "run-id"),
    ).resolves.toEqual({
      wrote: true,
    });
    expect(methods).toEqual(["GET", "GET", "GET", "DELETE", "GET", "GET"]);
  });

  it("fails readback when member absence is caused by concurrent group deletion", async () => {
    let deleted = false;
    const groupReadback = () =>
      deleted
        ? new Response(null, { status: 404 })
        : Response.json({ email: target.groupEmail, id: target.groupId });
    const client = new GoogleGroupMembershipWriter({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(
            Response.json({ "access_token": "token", "expires_in": 3600 }),
          );
        }
        if (url.pathname.endsWith("/immutable-group-id")) {
          return Promise.resolve(groupReadback());
        }
        if (url.searchParams.get("roles") === "OWNER") {
          return Promise.resolve(
            Response.json({
              members: [
                {
                  email: target.memberEmail,
                  id: target.memberId,
                  role: "OWNER",
                  type: "USER",
                },
                {
                  email: "other@company.test",
                  id: "other-owner-id",
                  role: "OWNER",
                  type: "USER",
                },
              ],
            }),
          );
        }
        if (init?.method === "DELETE") {
          deleted = true;
          return Promise.resolve(new Response(null, { status: 204 }));
        }
        return Promise.resolve(
          privilegedMemberReadback({ ...target, deleted }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.removePrivilegedDirectMember(target, "run-id"),
    ).rejects.toThrow("groups.get_for_member_removal HTTP 404");
  });

  it("fails closed without DELETE or role promotion when only one owner remains", async () => {
    const methods: string[] = [];
    const client = new GoogleGroupMembershipWriter({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(
            Response.json({ "access_token": "token", "expires_in": 3600 }),
          );
        }
        const method = init?.method ?? "GET";
        methods.push(method);
        if (url.pathname.endsWith("/immutable-group-id")) {
          return Promise.resolve(
            Response.json({ email: target.groupEmail, id: target.groupId }),
          );
        }
        if (url.searchParams.get("roles") === "OWNER") {
          return Promise.resolve(
            Response.json({
              members: [
                {
                  email: target.memberEmail,
                  id: target.memberId,
                  role: "OWNER",
                  type: "USER",
                },
              ],
            }),
          );
        }
        return Promise.resolve(
          Response.json({
            email: target.memberEmail,
            id: target.memberId,
            role: "OWNER",
            type: "USER",
          }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.removePrivilegedDirectMember(target, "run-id"),
    ).rejects.toThrow("requires at least two direct owners");
    expect(methods).not.toContain("DELETE");
    expect(methods).not.toContain("PATCH");
    expect(methods).not.toContain("POST");
    expect(methods).not.toContain("PUT");
  });

  it("pins the privileged role before any mutation", async () => {
    let deletes = 0;
    const client = new GoogleGroupMembershipWriter({
      adminSubject: "root-admin@company.test",
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com") {
          return Promise.resolve(
            Response.json({ "access_token": "token", "expires_in": 3600 }),
          );
        }
        if (init?.method === "DELETE") deletes++;
        if (url.pathname.endsWith("/immutable-group-id")) {
          return Promise.resolve(
            Response.json({ email: target.groupEmail, id: target.groupId }),
          );
        }
        return Promise.resolve(
          Response.json({
            email: target.memberEmail,
            id: target.memberId,
            role: "MANAGER",
            type: "USER",
          }),
        );
      },
      privateKey: await rsaPrivateKeyFixture(),
      serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
      sleep: () => Promise.resolve(),
      userProject: "workspace-sync-test",
    });

    await expect(
      client.removePrivilegedDirectMember(target, "run-id"),
    ).rejects.toThrow("changed before direct-membership removal");
    expect(deletes).toBe(0);
  });
});

describe("Slack channel client", () => {
  it("accepts omitted Slack user flags without treating them as false", async () => {
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const url = requestUrl(input);
        if (!url.pathname.endsWith("/users.list")) {
          return Promise.resolve(slackReadFetch(input));
        }
        return Promise.resolve(
          Response.json({
            members: [{ id: "U1", profile: { email: "person@company.test" } }],
            ok: true,
            "response_metadata": { "next_cursor": "" },
          }),
        );
      },
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    const result = await client.listSnapshot(
      ["marketing", "asks-marketing"],
      "run-id",
    );
    expect(result.members).toEqual([
      {
        id: "U1",
        profile: { email: "person@company.test" },
      },
    ]);
    expect(result.members[0]?.deleted).toBeUndefined();
    expect(result.members[0]?.["is_restricted"]).toBeUndefined();
  });

  it("hydrates current user-group channel associations outside the configured names", async () => {
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) =>
        Promise.resolve(slackReadFetchWithExtraAssociation(input)),
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    const result = await client.listSnapshot(
      ["marketing", "asks-marketing"],
      "run-id",
      undefined,
      true,
      ["group-marketing"],
    );

    expect(result.channels).toContainEqual(
      expect.objectContaining({
        id: "CEXTRA",
        name: "legacy-marketing-private",
      }),
    );
    expect(result.channels).not.toContainEqual(
      expect.objectContaining({ id: "CIGNORED" }),
    );
  });

  it("fails closed before writes when channel privacy metadata is missing", async () => {
    let writes = 0;
    const client = new OrgChannelSlackClient({
      fetchImpl: (input, init) => {
        if (init?.method === "POST") writes++;
        const response = slackReadFetch(input);
        const url = requestUrl(input);
        if (!url.pathname.endsWith("/conversations.info"))
          return Promise.resolve(response);
        return Promise.resolve(
          Response.json({
            channel: {
              id: "CASKS",
              "is_archived": false,
              name: "asks-marketing",
            },
            ok: true,
          }),
        );
      },
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    await expect(
      client.listSnapshot(["asks-marketing"], "run-id"),
    ).rejects.toThrow("is_private");
    expect(writes).toBe(0);
  });

  it("rejects channel identity readback for a different immutable ID", async () => {
    const client = new OrgChannelSlackClient({
      fetchImpl: () =>
        Promise.resolve(
          Response.json({
            channel: {
              id: "CWRONG",
              "is_archived": false,
              "is_private": false,
              name: "asks-marketing",
            },
            ok: true,
          }),
        ),
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    await expect(client.getChannelIdentity("CASKS", "run-id")).rejects.toThrow(
      "Slack channel identity readback mismatch",
    );
  });

  it("requires explicit external-sharing evidence before a provenance removal", async () => {
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => Promise.resolve(slackReadFetch(input)),
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    await expect(
      client.getChannelRemovalSafety("CPRIVATE", "run-id"),
    ).rejects.toThrow("is_ext_shared");
  });

  it("does not read membership after a deterministic channel kick application failure", async () => {
    const methods: string[] = [];
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        return Promise.resolve(
          Response.json({ error: "not_in_channel", ok: false }),
        );
      },
      token: "xoxp-test",
    });

    await expect(client.kick("CPRIVATE", "U1", "run-id")).rejects.toThrow(
      "Slack conversations.kick error: not_in_channel",
    );
    expect(methods).toEqual(["conversations.kick"]);
  });

  it("classifies an ambiguous channel kick without performing an unowned readback", async () => {
    const methods: string[] = [];
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        return Promise.reject(new Error("ambiguous network failure"));
      },
      token: "xoxp-test",
    });

    await expect(
      client.kick("CPRIVATE", "U1", "run-id"),
    ).rejects.toBeInstanceOf(SlackWriteOutcomeUnknownError);
    expect(methods).toEqual(["conversations.kick"]);
  });

  it("reads exact channel removal safety metadata", async () => {
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const url = requestUrl(input);
        return Promise.resolve(
          Response.json({
            channel: {
              id: url.searchParams.get("channel"),
              "is_archived": false,
              "is_ext_shared": false,
              "is_private": true,
              name: "qa",
            },
            ok: true,
          }),
        );
      },
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    await expect(
      client.getChannelRemovalSafety("CPRIVATE", "run-id"),
    ).resolves.toEqual({
      id: "CPRIVATE",
      isArchived: false,
      isExternallyShared: false,
      isPrivate: true,
      name: "qa",
    });
  });

  it("discovers channels by derived names and uses their runtime IDs", async () => {
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => Promise.resolve(slackReadFetch(input)),
      sleep: () => Promise.resolve(),
      token: "xoxp-test",
    });

    const result = await client.listSnapshot(
      ["marketing", "asks-marketing"],
      "run-id",
      undefined,
      true,
    );
    expect(result).toMatchObject({
      channels: [
        { id: "CPRIVATE", isPrivate: true, memberIds: ["U1", "U2"] },
        { id: "CASKS", isPrivate: false, memberIds: ["U1", "U2"] },
      ],
      scopes: [
        "channels:read",
        "groups:read",
        "usergroups:read",
        "users:read",
        "users:read.email",
      ],
      teamId: "TWORKSPACE",
      userGroups: [
        {
          channelIds: ["CASKS", "CPRIVATE"],
          handle: "group-marketing",
          id: "SMARKETING",
          isDisabled: false,
          name: "group-marketing",
          userIds: ["U1"],
        },
      ],
    });
  });

  it.each(["date_delete", "prefs", "users"])(
    "rejects an incomplete authoritative Slack user-group snapshot missing %s",
    async (missingField) => {
      const client = new OrgChannelSlackClient({
        fetchImpl: (input) => {
          const url = requestUrl(input);
          if (!url.pathname.endsWith("/usergroups.list")) {
            return Promise.resolve(slackReadFetch(input));
          }
          const userGroup = Object.fromEntries(
            Object.entries({
              "date_delete": 0,
              handle: "group-marketing",
              id: "SMARKETING",
              name: "group-marketing",
              prefs: { channels: ["CASKS"], groups: ["CPRIVATE"] },
              users: ["U1"],
            }).filter(([field]) => field !== missingField),
          );
          return Promise.resolve(
            Response.json({ ok: true, usergroups: [userGroup] }),
          );
        },
        sleep: () => Promise.resolve(),
        token: "xoxp-test",
      });

      await expect(
        client.listSnapshot(
          ["marketing", "asks-marketing"],
          "run-id",
          undefined,
          true,
        ),
      ).rejects.toThrow(missingField);
    },
  );

  it.each(["channels", "groups"])(
    "rejects an incomplete authoritative Slack user-group snapshot missing prefs.%s",
    async (missingPreference) => {
      const client = new OrgChannelSlackClient({
        fetchImpl: (input) => {
          const url = requestUrl(input);
          if (!url.pathname.endsWith("/usergroups.list")) {
            return Promise.resolve(slackReadFetch(input));
          }
          const prefs = Object.fromEntries(
            Object.entries({
              channels: ["CASKS"],
              groups: ["CPRIVATE"],
            }).filter(([field]) => field !== missingPreference),
          );
          return Promise.resolve(
            Response.json({
              ok: true,
              usergroups: [
                {
                  "date_delete": 0,
                  handle: "group-marketing",
                  id: "SMARKETING",
                  name: "Marketing",
                  prefs,
                  users: ["U1"],
                },
              ],
            }),
          );
        },
        sleep: () => Promise.resolve(),
        token: "xoxp-test",
      });

      await expect(
        client.listSnapshot(
          ["marketing", "asks-marketing"],
          "run-id",
          undefined,
          true,
        ),
      ).rejects.toThrow(missingPreference);
    },
  );

  it("uses only bounded user-group mutations for projected membership", async () => {
    const mutations: { body: unknown; method: string }[] = [];
    const client = new OrgChannelSlackClient({
      fetchImpl: async (input, init) => {
        const inputUrl = requestUrl(input);
        if (inputUrl.pathname.endsWith("/usergroups.list")) {
          return Response.json({
            ok: true,
            usergroups: [
              {
                "date_delete": 0,
                handle: "group-marketing",
                id: "SMARKETING",
                name: "Marketing",
                prefs: { channels: ["CASKS"], groups: ["CPRIVATE"] },
                users: [],
              },
            ],
          });
        }
        const body = isString(init?.body) ? init.body : "";
        const method = inputUrl.pathname.split("/").at(-1) ?? "";
        mutations.push({ body: JSON.parse(body), method });
        if (method === "usergroups.create") {
          return Response.json({ ok: true, usergroup: { id: "SMARKETING" } });
        }
        return Response.json({ ok: true });
      },
      token: "xoxp-test",
    });

    const userGroupId = await client.createUserGroup(
      "Marketing",
      "group-marketing",
      ["CASKS", "CPRIVATE"],
      "run-id",
    );
    await client.updateUserGroup(
      userGroupId,
      "Marketing",
      "group-marketing",
      ["CASKS", "CPRIVATE"],
      ["U1"],
      "additive",
      "run-id",
    );
    expect(mutations).toEqual([
      {
        body: {
          channels: "CASKS,CPRIVATE",
          handle: "group-marketing",
          name: "Marketing",
        },
        method: "usergroups.create",
      },
      {
        body: { usergroup: "SMARKETING", users: "U1" },
        method: "usergroups.users.update",
      },
    ]);
    expect(
      mutations.some((mutation) => mutation.method === "conversations.invite"),
    ).toBe(false);
  });

  it("renames a Slack channel by stable ID with the conversations.rename API", async () => {
    const mutations: { body: unknown; method: string }[] = [];
    const client = new OrgChannelSlackClient({
      fetchImpl: (input, init) => {
        const url = requestUrl(input);
        mutations.push({
          body: JSON.parse(isString(init?.body) ? init.body : "{}"),
          method: url.pathname.split("/").at(-1) ?? "",
        });
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    await client.renameChannel("CLEGACY", "eng", "run-id");

    expect(mutations).toEqual([
      {
        body: { channel: "CLEGACY", name: "eng" },
        method: "conversations.rename",
      },
    ]);
  });

  it("skips Slack membership replacement when the user group is already empty", async () => {
    const methods: string[] = [];
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        if (method === "usergroups.list") {
          return Promise.resolve(
            Response.json({
              ok: true,
              usergroups: [
                {
                  "date_delete": 0,
                  handle: "group-business",
                  id: "SBUSINESS",
                  name: "Business",
                  prefs: { channels: [], groups: [] },
                  users: [],
                },
              ],
            }),
          );
        }
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    await client.updateUserGroup(
      "SBUSINESS",
      "Business",
      "group-business",
      [],
      [],
      "additive",
      "run-id",
    );

    expect(methods).toEqual(["usergroups.list", "usergroups.list"]);
    expect(methods).not.toContain("usergroups.users.update");
  });

  it("preserves a concurrently visible protected Slack user-group member during a reviewed removal", async () => {
    const membershipWrites: string[] = [];
    const methods: string[] = [];
    let reads = 0;
    const memberships = [
      ["U1", "U2"],
      ["U1", "U2", "UROOTADMIN"],
    ] as const;
    const client = new OrgChannelSlackClient({
      fetchImpl: (input, init) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        if (method === "usergroups.list") {
          const users =
            memberships[Math.min(reads, memberships.length - 1)] ?? [];
          reads++;
          return Promise.resolve(slackUserGroupResponse(users));
        }
        if (method === "usergroups.users.update") {
          const body = JSON.parse(isString(init?.body) ? init.body : "{}") as {
            users?: string;
          };
          membershipWrites.push(body.users ?? "");
        }
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    await client.updateUserGroup(
      "SMARKETING",
      "Marketing",
      "group-marketing",
      [],
      ["U1"],
      "authoritative",
      "run-id",
      undefined,
      ["U1", "U2"],
      ["U2"],
    );

    expect(membershipWrites).toEqual(["U1,UROOTADMIN"]);
    expect(methods).not.toContain("usergroups.update");
  });

  it("uses only usergroups.users.update for a reviewed addition-only mutation and preserves concurrent members", async () => {
    const methods: string[] = [];
    const writes: unknown[] = [];
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input, init) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        if (method === "usergroups.list") {
          return Promise.resolve(
            slackUserGroupResponse(["U1", "UCONCURRENT"], ["CASKS"]),
          );
        }
        writes.push(JSON.parse(isString(init?.body) ? init.body : "{}"));
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    const applied = await client.addUserGroupMembers(
      "SMARKETING",
      "group-marketing",
      "Marketing",
      ["CASKS"],
      ["U1"],
      ["U2"],
      "run-id",
      undefined,
      onMutationStart,
    );

    expect(methods).toEqual(["usergroups.list", "usergroups.users.update"]);
    expect(writes).toEqual([
      { usergroup: "SMARKETING", users: "U1,U2,UCONCURRENT" },
    ]);
    expect(applied).toEqual({
      userIds: ["U1", "U2", "UCONCURRENT"],
      wrote: true,
    });
    expect(onMutationStart).toHaveBeenCalledOnce();
    expect(methods).not.toContain("usergroups.create");
    expect(methods).not.toContain("usergroups.update");
    expect(methods.some((method) => method.startsWith("conversations."))).toBe(
      false,
    );
  });

  it("reports a converged addition-only update as a no-op without starting a mutation", async () => {
    const methods: string[] = [];
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        return Promise.resolve(slackUserGroupResponse(["U1", "U2"], ["CASKS"]));
      },
      token: "xoxp-test",
    });

    await expect(
      client.addUserGroupMembers(
        "SMARKETING",
        "group-marketing",
        "Marketing",
        ["CASKS"],
        ["U1"],
        ["U2"],
        "run-id",
        undefined,
        onMutationStart,
      ),
    ).resolves.toEqual({ userIds: ["U1", "U2"], wrote: false });
    expect(methods).toEqual(["usergroups.list"]);
    expect(onMutationStart).not.toHaveBeenCalled();
  });

  it("blocks addition-only writes on metadata drift, a missing planned member, or an inexact batch", async () => {
    const cases = [
      {
        additions: ["U2"],
        expectedCurrent: ["U1"],
        expectedError: "changed before addition-only update",
        response: slackUserGroupResponse(["U1"], ["CMANUAL"]),
      },
      {
        additions: ["U2"],
        expectedCurrent: ["U1", "UMISSING"],
        expectedError: "lost a planned member before addition-only update",
        response: slackUserGroupResponse(["U1"], ["CASKS"]),
      },
      {
        additions: ["U2", "U2"],
        expectedCurrent: ["U1"],
        expectedError: "addition-only update is not an exact batch",
        response: slackUserGroupResponse(["U1"], ["CASKS"]),
      },
    ] as const;
    for (const testCase of cases) {
      let writes = 0;
      const client = new OrgChannelSlackClient({
        fetchImpl: (input) => {
          const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
          if (method === "usergroups.users.update") writes++;
          return Promise.resolve(
            method === "usergroups.list"
              ? testCase.response.clone()
              : Response.json({ ok: true }),
          );
        },
        token: "xoxp-test",
      });

      await expect(
        client.addUserGroupMembers(
          "SMARKETING",
          "group-marketing",
          "Marketing",
          ["CASKS"],
          testCase.expectedCurrent,
          testCase.additions,
          "run-id",
        ),
      ).rejects.toThrow(testCase.expectedError);
      expect(writes).toBe(0);
    }
  });

  it("accepts an ambiguous addition only after exact immutable-ID readback", async () => {
    let reads = 0;
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          reads++;
          return Promise.resolve(
            slackUserGroupResponse(reads === 1 ? ["U1"] : ["U1", "U2"], [
              "CASKS",
            ]),
          );
        }
        return Promise.reject(new Error("ambiguous network failure"));
      },
      token: "xoxp-test",
    });

    await expect(
      client.addUserGroupMembers(
        "SMARKETING",
        "group-marketing",
        "Marketing",
        ["CASKS"],
        ["U1"],
        ["U2"],
        "run-id",
        undefined,
        onMutationStart,
      ),
    ).resolves.toEqual({ userIds: ["U1", "U2"], wrote: true });
    expect(reads).toBe(2);
    expect(onMutationStart).toHaveBeenCalledOnce();
  });

  it("preserves an ambiguous addition failure when exact readback does not prove convergence", async () => {
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          return Promise.resolve(slackUserGroupResponse(["U1"], ["CASKS"]));
        }
        return Promise.reject(new Error("ambiguous network failure"));
      },
      token: "xoxp-test",
    });

    await expect(
      client.addUserGroupMembers(
        "SMARKETING",
        "group-marketing",
        "Marketing",
        ["CASKS"],
        ["U1"],
        ["U2"],
        "run-id",
        undefined,
        onMutationStart,
      ),
    ).rejects.toThrow("slack.usergroups.users.update network failure");
    expect(onMutationStart).toHaveBeenCalledOnce();
  });

  it.each(["remove", "add", "bulk"] as const)(
    "awaits the %s membership guard before transport and outside write recovery",
    async (kind) => {
      const fetchImpl = vi.fn<typeof fetch>(async () =>
        slackUserGroupResponse(["U1", "U2"], ["CASKS"]),
      );
      const client = new OrgChannelSlackClient({
        fetchImpl,
        token: "test-token",
      });
      const onMutationStart = vi.fn<() => void>();
      const rejected = new Error("identity_budget_exhausted");
      const guard = vi.fn(async () => {
        throw rejected;
      });
      let applied: Promise<unknown>;
      if (kind === "remove")
        applied = client.removeUserGroupMembers(
          "SMARKETING",
          "group-marketing",
          "Marketing",
          ["CASKS"],
          ["U1"],
          ["U1", "U2"],
          ["U2"],
          "run",
          undefined,
          onMutationStart,
          guard,
        );
      else if (kind === "add")
        applied = client.addUserGroupMembers(
          "SMARKETING",
          "group-marketing",
          "Marketing",
          ["CASKS"],
          ["U1", "U2"],
          ["U3"],
          "run",
          undefined,
          onMutationStart,
          guard,
        );
      else
        applied = client.updateUserGroup(
          "SMARKETING",
          "Marketing",
          "group-marketing",
          ["CASKS", "CNEW"],
          ["U1", "U2"],
          "additive",
          "run",
          undefined,
          ["U1", "U2"],
          [],
          guard,
          onMutationStart,
        );
      await expect(applied).rejects.toBe(rejected);
      expect(guard).toHaveBeenCalledExactlyOnceWith(
        { remove: ["U2"], add: ["U3"], bulk: [] }[kind],
      );
      expect(onMutationStart).not.toHaveBeenCalled();
      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(requestUrl(fetchImpl.mock.calls[0]?.[0] ?? "").pathname).toBe(
        "/api/usergroups.list",
      );
    },
  );

  it("rejects a second indirectly granted identity arriving during the budget await", async () => {
    let members = ["U1"];
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      slackUserGroupResponse(members, ["CASKS"]),
    );
    const client = new OrgChannelSlackClient({
      fetchImpl,
      token: "test-token",
    });
    const onMutationStart = vi.fn<() => void>();
    const guard = vi.fn(async () => {
      members = ["U1", "U2"];
    });
    await expect(
      client.updateUserGroup(
        "SMARKETING",
        "Marketing",
        "group-marketing",
        ["CASKS", "CNEW"],
        ["U1"],
        "additive",
        "run",
        undefined,
        ["U1"],
        [],
        guard,
        onMutationStart,
      ),
    ).rejects.toThrow("slack_budget_provider_group_changed");
    expect(guard).toHaveBeenCalledExactlyOnceWith([]);
    expect(onMutationStart).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(
      fetchImpl.mock.calls.map(([input]) => requestUrl(input).pathname),
    ).toEqual(["/api/usergroups.list", "/api/usergroups.list"]);
  });

  it("uses only usergroups.users.update for a reviewed removal-only mutation", async () => {
    const methods: string[] = [];
    const onMutationStart = vi.fn<() => void>();
    const writes: unknown[] = [];
    const client = new OrgChannelSlackClient({
      fetchImpl: (input, init) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        if (method === "usergroups.list") {
          return Promise.resolve(
            slackUserGroupResponse(["U1", "U2", "UCONCURRENT"], ["CASKS"]),
          );
        }
        writes.push(JSON.parse(isString(init?.body) ? init.body : "{}"));
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    const applied = await client.removeUserGroupMembers(
      "SMARKETING",
      "group-marketing",
      "Marketing",
      ["CASKS"],
      ["U1"],
      ["U1", "U2"],
      ["U2"],
      "run-id",
      undefined,
      onMutationStart,
    );

    expect(methods).toEqual(["usergroups.list", "usergroups.users.update"]);
    expect(writes).toEqual([
      { usergroup: "SMARKETING", users: "U1,UCONCURRENT" },
    ]);
    expect(applied).toEqual({ userIds: ["U1", "UCONCURRENT"], wrote: true });
    expect(onMutationStart).toHaveBeenCalledOnce();
    expect(methods).not.toContain("usergroups.create");
    expect(methods).not.toContain("usergroups.update");
    expect(methods.some((method) => method.startsWith("conversations."))).toBe(
      false,
    );
    expect(methods.some((method) => method.startsWith("chat."))).toBe(false);
  });

  it.each(["source-drift", "expired"] as const)(
    "blocks reviewed removal %s after the last group reread",
    async (reason) => {
      let reads = 0;
      let sourceChanged = false;
      const methods: string[] = [];
      const started = vi.fn<() => void>();
      const beforeWrite = vi.fn(async () => undefined);
      const finalSource = {
        assertFinalSourceAuthority: vi.fn(async () => {
          if (sourceChanged && reason === "source-drift")
            throw new Error(reason);
        }),
        assertFreshPlan: vi.fn(() => {
          if (sourceChanged && reason === "expired") throw new Error(reason);
        }),
      };
      const client = new OrgChannelSlackClient({
        token: "xoxp-test",
        fetchImpl: (input) => {
          const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
          methods.push(method);
          if (method === "usergroups.list") {
            reads += 1;
            if (reads === 2) sourceChanged = true;
            return Promise.resolve(
              slackUserGroupResponse(["U1", "U2"], ["CASKS"]),
            );
          }
          return Promise.resolve(Response.json({ ok: true }));
        },
      });
      await expect(
        client.removeUserGroupMembers(
          "SMARKETING",
          "group-marketing",
          "Marketing",
          ["CASKS"],
          ["U1"],
          ["U1", "U2"],
          ["U2"],
          "run-id",
          undefined,
          started,
          beforeWrite,
          finalSource,
        ),
      ).rejects.toThrow(reason);
      expect(methods).toEqual(["usergroups.list", "usergroups.list"]);
      expect(beforeWrite).toHaveBeenCalledExactlyOnceWith(["U2"]);
      expect(finalSource.assertFinalSourceAuthority).toHaveBeenCalledOnce();
      expect(started).not.toHaveBeenCalled();
    },
  );

  it("reports a converged removal-only update as a no-op without starting a mutation", async () => {
    const methods: string[] = [];
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        methods.push(method);
        return Promise.resolve(slackUserGroupResponse(["U1"], ["CASKS"]));
      },
      token: "xoxp-test",
    });

    await expect(
      client.removeUserGroupMembers(
        "SMARKETING",
        "group-marketing",
        "Marketing",
        ["CASKS"],
        ["U1"],
        ["U1", "U2"],
        ["U2"],
        "run-id",
        undefined,
        onMutationStart,
      ),
    ).resolves.toEqual({ userIds: ["U1"], wrote: false });
    expect(methods).toEqual(["usergroups.list"]);
    expect(onMutationStart).not.toHaveBeenCalled();
  });

  it("blocks removal-only writes on metadata drift, unrelated disappearance, or empty membership", async () => {
    const cases = [
      {
        expectedError: "changed before removal-only update",
        response: slackUserGroupResponse(["U1", "U2"], ["CMANUAL"]),
        desired: ["U1"],
        expectedCurrent: ["U1", "U2"],
        removed: ["U2"],
      },
      {
        expectedError: "lost unreviewed members before update",
        response: slackUserGroupResponse(["U2"], ["CASKS"]),
        desired: ["U1"],
        expectedCurrent: ["U1", "U2"],
        removed: ["U2"],
      },
      {
        expectedError: "removal-only update would empty membership",
        response: slackUserGroupResponse(["U2"], ["CASKS"]),
        desired: [],
        expectedCurrent: ["U2"],
        removed: ["U2"],
      },
    ] as const;
    for (const testCase of cases) {
      let writes = 0;
      const client = new OrgChannelSlackClient({
        fetchImpl: (input) => {
          const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
          if (method === "usergroups.users.update") writes++;
          return Promise.resolve(
            method === "usergroups.list"
              ? testCase.response.clone()
              : Response.json({ ok: true }),
          );
        },
        token: "xoxp-test",
      });
      await expect(
        client.removeUserGroupMembers(
          "SMARKETING",
          "group-marketing",
          "Marketing",
          ["CASKS"],
          testCase.desired,
          testCase.expectedCurrent,
          testCase.removed,
          "run-id",
        ),
      ).rejects.toThrow(testCase.expectedError);
      expect(writes).toBe(0);
    }
  });

  it("accepts an ambiguous removal only after exact immutable-ID readback", async () => {
    let reads = 0;
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          reads++;
          return Promise.resolve(
            slackUserGroupResponse(reads === 1 ? ["U1", "U2"] : ["U1"], [
              "CASKS",
            ]),
          );
        }
        return Promise.reject(new Error("ambiguous network failure"));
      },
      token: "xoxp-test",
    });

    await expect(
      client.removeUserGroupMembers(
        "SMARKETING",
        "group-marketing",
        "Marketing",
        ["CASKS"],
        ["U1"],
        ["U1", "U2"],
        ["U2"],
        "run-id",
        undefined,
        onMutationStart,
      ),
    ).resolves.toEqual({ userIds: ["U1"], wrote: true });
    expect(reads).toBe(2);
    expect(onMutationStart).toHaveBeenCalledOnce();
  });

  it("reports mutation start when an ambiguous removal cannot be verified", async () => {
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          return Promise.resolve(
            slackUserGroupResponse(["U1", "U2"], ["CASKS"]),
          );
        }
        return Promise.reject(new Error("ambiguous network failure"));
      },
      token: "xoxp-test",
    });

    await expect(
      client.removeUserGroupMembers(
        "SMARKETING",
        "group-marketing",
        "Marketing",
        ["CASKS"],
        ["U1"],
        ["U1", "U2"],
        ["U2"],
        "run-id",
        undefined,
        onMutationStart,
      ),
    ).rejects.toThrow("slack.usergroups.users.update network failure");
    expect(onMutationStart).toHaveBeenCalledOnce();
  });

  it("aborts a Slack user-group removal after an unrelated concurrent member disappears", async () => {
    let reads = 0;
    let writes = 0;
    const memberships = [["U1", "U2"], ["U2"]] as const;
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          const users =
            memberships[Math.min(reads, memberships.length - 1)] ?? [];
          reads++;
          return Promise.resolve(slackUserGroupResponse(users));
        }
        if (method === "usergroups.users.update") writes++;
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    await expect(
      client.updateUserGroup(
        "SMARKETING",
        "Marketing",
        "group-marketing",
        [],
        ["U1"],
        "authoritative",
        "run-id",
        undefined,
        ["U1", "U2"],
        ["U2"],
      ),
    ).rejects.toThrow(
      "Slack user group @group-marketing lost unreviewed members before update",
    );
    expect(writes).toBe(0);
  });

  it("removes only an explicitly reviewed Slack user-group channel association", async () => {
    let channels = ["CASKS", "CMANUAL", "CRELEASE"];
    const writes: unknown[] = [];
    const onMutationStart = vi.fn<() => void>();
    const client = new OrgChannelSlackClient({
      fetchImpl: async (input, init) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          return slackUserGroupResponse(["U1"], channels);
        }
        if (method === "usergroups.update") {
          writes.push(await new Request(input, init).json());
          channels = ["CASKS", "CMANUAL"];
        }
        return Response.json({ ok: true });
      },
      token: "xoxp-test",
    });

    await client.updateUserGroup(
      "SMARKETING",
      "Marketing",
      "group-marketing",
      ["CASKS"],
      ["U1"],
      "additive",
      "run-id",
      undefined,
      ["U1"],
      [],
      undefined,
      onMutationStart,
      ["CASKS", "CRELEASE"],
      ["CRELEASE"],
    );

    expect(writes).toEqual([
      {
        channels: "CASKS,CMANUAL",
        handle: "group-marketing",
        name: "Marketing",
        usergroup: "SMARKETING",
      },
    ]);
    expect(onMutationStart).toHaveBeenCalledOnce();
  });

  it("rejects an inconsistent Slack user-group channel removal review before mutation", async () => {
    let writes = 0;
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          return Promise.resolve(
            slackUserGroupResponse(["U1"], ["CASKS", "CRELEASE"]),
          );
        }
        writes++;
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    await expect(
      client.updateUserGroup(
        "SMARKETING",
        "Marketing",
        "group-marketing",
        ["CASKS"],
        ["U1"],
        "additive",
        "run-id",
        undefined,
        ["U1"],
        [],
        undefined,
        undefined,
        ["CASKS"],
        ["CRELEASE"],
      ),
    ).rejects.toThrow(
      "Slack user group @group-marketing channel removal review is inconsistent",
    );
    expect(writes).toBe(0);
  });

  it("aborts a reviewed removal when a channel association appears immediately before the write", async () => {
    let reads = 0;
    let writes = 0;
    const client = new OrgChannelSlackClient({
      fetchImpl: (input) => {
        const method = requestUrl(input).pathname.split("/").at(-1) ?? "";
        if (method === "usergroups.list") {
          const response = slackUserGroupResponse(
            ["U1", "U2"],
            reads === 0 ? [] : ["CMANUAL"],
          );
          reads++;
          return Promise.resolve(response);
        }
        if (method === "usergroups.users.update") writes++;
        return Promise.resolve(Response.json({ ok: true }));
      },
      token: "xoxp-test",
    });

    await expect(
      client.updateUserGroup(
        "SMARKETING",
        "Marketing",
        "group-marketing",
        [],
        ["U1"],
        "authoritative",
        "run-id",
        undefined,
        ["U1", "U2"],
        ["U2"],
      ),
    ).rejects.toThrow(
      "Slack user group @group-marketing gained an unreviewed channel association before removal",
    );
    expect(writes).toBe(0);
  });
});
