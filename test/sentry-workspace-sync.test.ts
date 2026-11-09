import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { RetryDeadlineExceededError } from "../src/org-sync/http.ts";
import {
  type ISentryWorkspaceClient,
  SentryOrganizationMemberSchema,
  SentryWorkspaceAuthorityBootstrapSchema,
  SentryWorkspaceBoundExceededError,
  SentryWorkspaceCapabilityError,
  SentryWorkspaceClient,
  SentryWorkspaceProviderContractError,
  SentryWorkspaceRequestError,
  type SentryWorkspaceSnapshot,
  SentryWorkspaceUnexpectedMutationStatusError,
  SentryWorkspaceUnsupportedCredentialError,
} from "../src/workspace-directory/sentry-workspace-client.ts";
import {
  applySentryWorkspaceAction as applySentryWorkspaceActionWithAuthority,
  applySentryWorkspacePlanAction as applySentryWorkspacePlanActionWithAuthority,
  auditSentryWorkspaceSync,
  planSentryWorkspaceSync,
  type SentryWorkspaceAction,
  SentryWorkspacePlanBoundError,
  SentryWorkspaceProjectTeamError,
  SentryWorkspaceReadbackError,
} from "../src/workspace-directory/sentry-workspace-sync.ts";

const API = "https://sentry.io/api/0";
const allowWrite = () => Promise.resolve();

function applySentryWorkspaceAction(
  sentryClient: ISentryWorkspaceClient,
  action: SentryWorkspaceAction,
) {
  return applySentryWorkspaceActionWithAuthority(
    sentryClient,
    action,
    allowWrite,
  );
}

function applySentryWorkspacePlanAction(
  activeGoogleMembers: readonly string[],
  sentryClient: ISentryWorkspaceClient,
  action: SentryWorkspaceAction,
  expectedPlanHash: string,
) {
  return applySentryWorkspacePlanActionWithAuthority(
    activeGoogleMembers,
    sentryClient,
    action,
    expectedPlanHash,
    allowWrite,
  );
}

function member(
  id: string,
  email: string,
  options: {
    expired?: boolean;
    orgRole?: "admin" | "billing" | "manager" | "member" | "owner";
    pending?: boolean;
    role?: "admin" | "billing" | "manager" | "member" | "owner";
    teamRole?: "admin" | "contributor" | null;
    teams?: string[];
  } = {},
) {
  return {
    email,
    expired: options.expired ?? false,
    id,
    orgRole: options.orgRole ?? "member",
    pending: options.pending ?? false,
    role: options.role ?? "member",
    teamRoles:
      options.teamRole === undefined
        ? []
        : [{ role: options.teamRole, teamSlug: "platform" }],
    ...(!(options.teams === undefined) && { teams: options.teams }),
    user: { email, id: `user-${id}` },
  };
}

function snapshot(
  overrides: Partial<SentryWorkspaceSnapshot> = {},
): SentryWorkspaceSnapshot {
  return {
    organizationMembers: [],
    projectTeams: [{ id: "project-team-1", slug: "platform" }],
    teamMembers: [],
    ...overrides,
  };
}

function urlOf(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : input.toString();
}

function requestBody(init: RequestInit | undefined): string {
  return z.string().parse(init?.body);
}

function client(
  fetchImpl: typeof fetch,
  overrides: {
    maxPages?: number;
    maxRequests?: number;
    readDeadlineMs?: number;
    readMaxAttempts?: number;
    retrySleep?: (milliseconds: number) => Promise<void>;
  } = {},
) {
  return new SentryWorkspaceClient({
    fetchImpl,
    organizationSlug: "example",
    projectSlug: "platform",
    teamSlug: "platform",
    token: "secret-test-token",
    ...overrides,
  });
}

function authorityFetch(options: {
  effectiveTeamRole: "admin" | "contributor" | null;
  explicitTeamRole?: unknown;
  isMember: boolean;
  organizationRole: "admin" | "billing" | "manager" | "member" | "owner";
}) {
  const actor = {
    email: "actor@company.test",
    expired: false,
    id: "5001",
    orgRole: options.organizationRole,
    pending: false,
    role: options.organizationRole,
    teamRoles:
      options.explicitTeamRole === undefined
        ? []
        : [{ role: options.explicitTeamRole, teamSlug: "platform" }],
    teams: options.isMember ? ["platform"] : [],
    user: { email: "actor@company.test", id: "1001" },
  };
  return vi.fn<typeof fetch>(async (input) => {
    const url = urlOf(input);
    if (url === `${API}/`) {
      return Response.json({
        auth: { scopes: ["member:write"] },
        user: { id: "1001" },
      });
    }
    if (url.endsWith("/organizations/example/")) {
      return Response.json({
        id: "2001",
        slug: "example",
        status: { id: "active" },
      });
    }
    if (url.includes("/projects/")) {
      return Response.json({
        id: "3001",
        organization: { id: "2001", slug: "example" },
        slug: "platform",
        status: "active",
        teams: [{ id: "4001", slug: "platform" }],
      });
    }
    if (url.includes("/teams/")) {
      return Response.json({
        hasAccess: true,
        id: "4001",
        isMember: options.isMember,
        organization: { id: "2001", slug: "example" },
        slug: "platform",
        teamRole: options.effectiveTeamRole,
      });
    }
    return Response.json(url.endsWith("/members/5001/") ? actor : [actor]);
  });
}

interface MutableSentryState {
  organizationMembers: SentryWorkspaceSnapshot["organizationMembers"][number][];
  projectTeams: SentryWorkspaceSnapshot["projectTeams"][number][];
  teamMembers: SentryWorkspaceSnapshot["teamMembers"][number][];
}

function readSentryState(url: string, state: MutableSentryState): Response {
  if (url === `${API}/organizations/example/members/`) {
    return Response.json(
      state.organizationMembers.map(
        ({ role: _role, teamRoles: _teamRoles, teams: _teams, ...entry }) =>
          entry,
      ),
    );
  }
  const memberMatch = /\/organizations\/example\/members\/([^/]+)\/$/u.exec(
    url,
  );
  if (memberMatch?.[1] !== undefined) {
    const selected = state.organizationMembers.find(
      ({ id }) => id === memberMatch[1],
    );
    return selected === undefined
      ? new Response(null, { status: 404 })
      : Response.json({
          ...selected,
          teamRoles: (selected.teams ?? []).map((teamSlug) => ({
            role: "contributor" as const,
            teamSlug,
          })),
          teams: selected.teams ?? [],
        });
  }
  if (url === `${API}/teams/example/platform/members/`)
    return Response.json(state.teamMembers);
  if (url === `${API}/projects/example/platform/teams/`)
    return Response.json(state.projectTeams);
  return new Response(null, { status: 404 });
}

function mutateSentryState(
  url: string,
  init: RequestInit | undefined,
  state: MutableSentryState,
) {
  const addMatch =
    /\/organizations\/example\/members\/([^/]+)\/teams\/platform\/$/u.exec(url);
  if (addMatch?.[1] !== undefined) {
    const selected = state.organizationMembers.find(
      ({ id }) => id === addMatch[1],
    );
    if (selected !== undefined) {
      selected.teams = [...new Set([...(selected.teams ?? []), "platform"])];
      if (
        !selected.pending &&
        !state.teamMembers.some(({ id }) => id === selected.id)
      ) {
        state.teamMembers.push(selected);
      }
    }
    return Response.json({}, { status: 201 });
  }
  const reinviteMatch = /\/organizations\/example\/members\/([^/]+)\/$/u.exec(
    url,
  );
  if (init?.method === "PUT" && reinviteMatch?.[1] !== undefined) {
    const selected = state.organizationMembers.find(
      ({ id }) => id === reinviteMatch[1],
    );
    if (selected === undefined) return new Response(null, { status: 404 });
    selected.expired = false;
    return Response.json(selected);
  }
  if (url === `${API}/organizations/example/members/`) {
    const body = JSON.parse(requestBody(init)) as { email: string };
    const invited = member("new-id", body.email, {
      pending: true,
      teams: ["platform"],
    });
    state.organizationMembers.push(invited);
    return Response.json({}, { status: 201 });
  }
  return new Response(null, { status: 404 });
}

function mutableSentryFetch(initial: SentryWorkspaceSnapshot) {
  const state: MutableSentryState = {
    organizationMembers: [...initial.organizationMembers],
    projectTeams: [...initial.projectTeams],
    teamMembers: [...initial.teamMembers],
  };
  const fetchImpl = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      return method === "GET"
        ? readSentryState(url, state)
        : mutateSentryState(url, init, state);
    },
  );
  return { fetchImpl, state };
}

describe("Sentry workspace planning", () => {
  it("plans only additive changes for active Google team-platform members", () => {
    const current = snapshot({
      organizationMembers: [
        member("1", "existing@company.test"),
        member("2", "expired@company.test", { expired: true, pending: true }),
        member("3", "pending@company.test", { pending: true }),
        member("6", "pending-converged@company.test", {
          pending: true,
          teams: ["platform"],
        }),
        member("4", "converged@company.test"),
        member("5", "unmanaged@company.test"),
      ],
      teamMembers: [
        member("4", "converged@company.test"),
        member("5", "unmanaged@company.test"),
      ],
    });

    expect(
      planSentryWorkspaceSync(
        [
          "NEW@company.test",
          "existing@company.test",
          "expired@company.test",
          "pending@company.test",
          "pending-converged@company.test",
          "converged@company.test",
        ],
        current,
      ),
    ).toEqual({
      actions: [
        {
          email: "existing@company.test",
          memberId: "1",
          type: "add-team-member",
        },
        {
          email: "expired@company.test",
          memberId: "2",
          type: "reinvite-expired",
        },
        { email: "new@company.test", type: "invite" },
        {
          email: "pending@company.test",
          memberId: "3",
          type: "repair-pending-invite",
        },
      ],
      activeGoogleMembers: [
        "converged@company.test",
        "existing@company.test",
        "expired@company.test",
        "new@company.test",
        "pending-converged@company.test",
        "pending@company.test",
      ],
    });
  });

  it("fails closed unless the platform team is attached to the project", () => {
    expect(() =>
      planSentryWorkspaceSync(
        ["member@company.test"],
        snapshot({ projectTeams: [] }),
      ),
    ).toThrow(SentryWorkspaceProjectTeamError);
  });

  it("fails closed on ambiguous identities and bounded authority/action sets", () => {
    expect(() =>
      planSentryWorkspaceSync(
        ["duplicate@company.test"],
        snapshot({
          organizationMembers: [
            member("1", "duplicate@company.test"),
            member("2", "duplicate@company.test"),
          ],
        }),
      ),
    ).toThrow("sentry_workspace_duplicate_organization_identity");
    expect(() =>
      planSentryWorkspaceSync(
        Array.from(
          { length: 51 },
          (_, index) => `member-${String(index)}@company.test`,
        ),
        snapshot(),
      ),
    ).toThrow(SentryWorkspacePlanBoundError);
    expect(() =>
      planSentryWorkspaceSync(
        Array.from(
          { length: 26 },
          (_, index) => `member-${String(index)}@company.test`,
        ),
        snapshot(),
      ),
    ).toThrow("sentry_workspace_action_bound_exceeded");
  });

  it.each(["admin", "billing", "manager", "owner"] as const)(
    "does not grant missing team access to a Sentry %s",
    (orgRole) => {
      expect(
        planSentryWorkspaceSync(
          ["protected@company.test"],
          snapshot({
            organizationMembers: [
              member("protected-1", "protected@company.test", {
                orgRole,
                role: orgRole,
              }),
            ],
          }),
        ).actions,
      ).toEqual([]);
    },
  );

  it.each(["admin", null] as const)(
    "does not modify a target with protected or unknown team role %s",
    (teamRole) => {
      const protectedMember = member(
        "team-protected-1",
        "team-protected@company.test",
        {
          teamRole,
        },
      );
      protectedMember.teamRoles = [
        { role: teamRole, teamSlug: "another-team" },
      ];
      expect(
        planSentryWorkspaceSync(
          ["team-protected@company.test"],
          snapshot({
            organizationMembers: [protectedMember],
          }),
        ).actions,
      ).toEqual([]);
    },
  );

  it("rejects unknown Sentry organization roles", () => {
    expect(() =>
      SentryOrganizationMemberSchema.parse({
        ...member("unknown-1", "unknown@company.test"),
        orgRole: "superuser",
      }),
    ).toThrow();
  });
});

describe("Sentry workspace client and execution", () => {
  it("retries transient read-only failures with bounded backoff", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(null, { headers: { "retry-after": "1" }, status: 429 }),
      )
      .mockRejectedValueOnce(new TypeError("transient network failure"))
      .mockResolvedValueOnce(
        Response.json({
          auth: { scopes: ["member:admin"] },
          user: { id: "1001" },
        }),
      );
    const retrySleep = vi.fn(async (_milliseconds: number) => undefined);

    await expect(
      client(fetchImpl, { retrySleep }).assertCanRegenerateInvite(),
    ).resolves.toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(retrySleep).toHaveBeenCalledTimes(2);
    expect(retrySleep.mock.calls[0]?.[0]).toBe(1_000);
  });

  it("omits rejected network error text from Sentry retry logs", async () => {
    const secret = "secret-test-token actor@company.test";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError(secret))
      .mockResolvedValueOnce(
        Response.json({
          auth: { scopes: ["member:admin"] },
          user: { id: "1001" },
        }),
      );

    await expect(
      client(fetchImpl, {
        retrySleep: async () => undefined,
      }).assertCanRegenerateInvite(),
    ).resolves.toBeUndefined();

    const retryLog = warn.mock.calls
      .map(([entry]) => String(entry))
      .find((entry) => entry.includes("org_sync.network_retry"));
    warn.mockRestore();
    expect(retryLog).toBeDefined();
    expect(JSON.parse(retryLog ?? "{}")).not.toHaveProperty("error");
    expect(retryLog).not.toContain(secret);
  });

  it("counts every read retry against the physical request budget", async () => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response(null, { status: 503 }),
    );

    await expect(
      client(fetchImpl, {
        maxRequests: 1,
        retrySleep: async () => undefined,
      }).assertCanRegenerateInvite(),
    ).rejects.toBeInstanceOf(SentryWorkspaceBoundExceededError);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("stops read retries at the shared operation deadline and does not retry permanent errors", async () => {
    const rateLimited = vi.fn<typeof fetch>(
      async () =>
        new Response(null, { headers: { "retry-after": "60" }, status: 429 }),
    );
    await expect(
      client(rateLimited, {
        readDeadlineMs: 1_000,
      }).assertCanRegenerateInvite(),
    ).rejects.toBeInstanceOf(RetryDeadlineExceededError);
    expect(rateLimited).toHaveBeenCalledOnce();

    const forbidden = vi.fn<typeof fetch>(
      async () => new Response(null, { status: 403 }),
    );
    await expect(
      client(forbidden).assertCanRegenerateInvite(),
    ).rejects.toMatchObject({
      status: 403,
    });
    expect(forbidden).toHaveBeenCalledOnce();
  });

  it("never retries a rejected Sentry mutation", async () => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response(null, { status: 503 }),
    );

    await expect(
      client(fetchImpl).invite("engineer@company.test", allowWrite),
    ).rejects.toMatchObject({
      status: 503,
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fetchImpl.mock.calls[0]?.[1]?.method).toBe("POST");
  });

  it("reads coherent manager authority with effective team admin and zero writes", async () => {
    const actor = {
      email: "actor@company.test",
      expired: false,
      id: "5001",
      orgRole: "manager",
      pending: false,
      role: "manager",
      teamRoles: [{ role: "contributor", teamSlug: "platform" }],
      teams: ["platform"],
      user: { email: "actor@company.test", id: "1001" },
    };
    const responses = new Map<string, unknown>([
      [
        `${API}/`,
        {
          auth: { scopes: ["team:write", "member:write", "team:write"] },
          user: { id: "1001" },
        },
      ],
      [
        `${API}/organizations/example/`,
        { id: "2001", slug: "example", status: { id: "active" } },
      ],
      [
        `${API}/projects/example/platform/`,
        {
          id: "3001",
          organization: { id: "2001", slug: "example" },
          slug: "platform",
          status: "active",
          teams: [{ id: "4001", slug: "platform" }],
        },
      ],
      [
        `${API}/teams/example/platform/`,
        {
          hasAccess: true,
          id: "4001",
          isMember: true,
          organization: { id: "2001", slug: "example" },
          slug: "platform",
          teamRole: "admin",
        },
      ],
      [`${API}/organizations/example/members/?query=user.id%3A1001`, [actor]],
      [`${API}/organizations/example/members/5001/`, actor],
    ]);
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const response = responses.get(urlOf(input));
      return response === undefined
        ? new Response(null, { status: 404 })
        : Response.json(response);
    });

    await expect(client(fetchImpl).authorityBootstrap()).resolves.toEqual({
      actor: {
        id: "1001",
        orgRole: "manager",
        role: "manager",
        scopes: ["member:write", "team:write"],
        teamRole: "admin",
      },
      mode: "audit",
      organization: { id: "2001", slug: "example" },
      project: { id: "3001", slug: "platform" },
      team: { id: "4001", slug: "platform" },
      writes: 0,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(6);
    for (const [, init] of fetchImpl.mock.calls) {
      expect(init?.method).toBe("GET");
      expect(init?.redirect).toBe("manual");
    }
  });

  it("fails closed on unsupported credentials and incoherent tenant identity", async () => {
    const unsupported = vi.fn<typeof fetch>(async () =>
      Response.json({ auth: { scopes: ["member:write"] }, user: null }),
    );
    await expect(
      client(unsupported).authorityBootstrap(),
    ).rejects.toBeInstanceOf(SentryWorkspaceUnsupportedCredentialError);
    expect(unsupported).toHaveBeenCalledOnce();

    const incoherent = vi.fn<typeof fetch>(async (input) => {
      const url = urlOf(input);
      if (url === `${API}/`) {
        return Response.json({
          auth: { scopes: ["member:write"] },
          user: { id: "1001" },
        });
      }
      if (url.endsWith("/organizations/example/")) {
        return Response.json({
          id: "2001",
          slug: "example",
          status: { id: "active" },
        });
      }
      if (url.includes("/projects/")) {
        return Response.json({
          id: "3001",
          organization: { id: "9999", slug: "example" },
          slug: "platform",
          status: "active",
          teams: [{ id: "4001", slug: "platform" }],
        });
      }
      if (url.includes("/teams/")) {
        return Response.json({
          hasAccess: true,
          id: "4001",
          isMember: true,
          organization: { id: "2001", slug: "example" },
          slug: "platform",
          teamRole: "admin",
        });
      }
      if (url.endsWith("/members/member-1/")) {
        return Response.json({
          expired: false,
          id: "member-1",
          orgRole: "manager",
          pending: false,
          role: "manager",
          teamRoles: [{ role: "admin", teamSlug: "platform" }],
          teams: ["platform"],
          user: { id: "1001" },
        });
      }
      return Response.json([
        {
          expired: false,
          id: "member-1",
          orgRole: "manager",
          pending: false,
          role: "manager",
          teamRoles: [{ role: "admin", teamSlug: "platform" }],
          teams: ["platform"],
          user: { id: "1001" },
        },
      ]);
    });
    await expect(client(incoherent).authorityBootstrap()).rejects.toMatchObject(
      {
        name: "SentryWorkspaceAuthorityBootstrapError",
        stage: "tenant-identity",
      },
    );
    expect(
      incoherent.mock.calls.every(([, init]) => init?.method === "GET"),
    ).toBe(true);
  });

  it("rejects conflicting actor team-role evidence", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = urlOf(input);
      if (url === `${API}/`) {
        return Response.json({
          auth: { scopes: ["member:write"] },
          user: { id: "1001" },
        });
      }
      if (url.endsWith("/organizations/example/")) {
        return Response.json({
          id: "2001",
          slug: "example",
          status: { id: "active" },
        });
      }
      if (url.includes("/projects/")) {
        return Response.json({
          id: "3001",
          organization: { id: "2001", slug: "example" },
          slug: "platform",
          status: "active",
          teams: [{ id: "4001", slug: "platform" }],
        });
      }
      if (url.includes("/teams/")) {
        return Response.json({
          hasAccess: true,
          id: "4001",
          isMember: true,
          organization: { id: "2001", slug: "example" },
          slug: "platform",
          teamRole: "contributor",
        });
      }
      if (url.endsWith("/members/5001/")) {
        return Response.json({
          expired: false,
          id: "5001",
          orgRole: "manager",
          pending: false,
          role: "manager",
          teamRoles: [{ role: "admin", teamSlug: "platform" }],
          teams: ["platform"],
          user: { id: "1001" },
        });
      }
      return Response.json([
        {
          expired: false,
          id: "5001",
          orgRole: "manager",
          pending: false,
          role: "manager",
          teamRoles: [{ role: "admin", teamSlug: "platform" }],
          teams: ["platform"],
          user: { id: "1001" },
        },
      ]);
    });

    await expect(client(fetchImpl).authorityBootstrap()).rejects.toMatchObject({
      name: "SentryWorkspaceAuthorityBootstrapError",
      stage: "actor-team-role",
    });
    expect(
      fetchImpl.mock.calls.every(([, init]) => init?.method === "GET"),
    ).toBe(true);
  });

  it.each([
    ["admin", "contributor", true, "admin"],
    ["owner", "contributor", true, "admin"],
    ["member", "contributor", true, "contributor"],
    ["member", "admin", true, "admin"],
    ["member", null, true, "contributor"],
    ["owner", undefined, false, null],
  ] as const)(
    "derives %s organization authority with stored team role %s and membership %s as %s",
    async (organizationRole, explicitTeamRole, isMember, effectiveTeamRole) => {
      const fetchImpl = authorityFetch({
        effectiveTeamRole,
        explicitTeamRole,
        isMember,
        organizationRole,
      });

      await expect(
        client(fetchImpl).authorityBootstrap(),
      ).resolves.toMatchObject({
        actor: { orgRole: organizationRole, teamRole: effectiveTeamRole },
      });
      expect(
        fetchImpl.mock.calls.every(([, init]) => init?.method === "GET"),
      ).toBe(true);
    },
  );

  it.each([
    {
      effectiveTeamRole: null,
      explicitTeamRole: "contributor",
      isMember: false,
    },
    {
      effectiveTeamRole: "contributor",
      explicitTeamRole: undefined,
      isMember: true,
    },
  ] as const)(
    "rejects incoherent actor membership evidence %#",
    async (roleEvidence) => {
      await expect(
        client(
          authorityFetch({ ...roleEvidence, organizationRole: "member" }),
        ).authorityBootstrap(),
      ).rejects.toMatchObject({
        name: "SentryWorkspaceAuthorityBootstrapError",
        stage: "actor-team-role",
      });
    },
  );

  it("rejects an unknown stored actor team role", async () => {
    await expect(
      client(
        authorityFetch({
          effectiveTeamRole: "contributor",
          explicitTeamRole: "unknown-role",
          isMember: true,
          organizationRole: "member",
        }),
      ).authorityBootstrap(),
    ).rejects.toBeInstanceOf(SentryWorkspaceProviderContractError);
  });

  it("rejects provider-controlled strings that are unsafe for protected CI output", () => {
    const safe = {
      actor: {
        id: "1001",
        orgRole: "manager" as const,
        role: "manager" as const,
        scopes: ["member:write"],
        teamRole: "admin" as const,
      },
      mode: "audit" as const,
      organization: { id: "2001", slug: "example" },
      project: { id: "3001", slug: "platform" },
      team: { id: "4001", slug: "platform" },
      writes: 0 as const,
    };
    expect(() =>
      SentryWorkspaceAuthorityBootstrapSchema.parse({
        ...safe,
        actor: { ...safe.actor, id: "actor@company.test" },
      }),
    ).toThrow();
    expect(() =>
      SentryWorkspaceAuthorityBootstrapSchema.parse({
        ...safe,
        actor: { ...safe.actor, scopes: ["token secret value"] },
      }),
    ).toThrow();
  });

  it("requires the exact member-admin capability before expired-invite regeneration", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      Response.json({
        auth: { scopes: ["member:invite", "member:write"] },
        user: { id: "1001" },
      }),
    );
    await expect(
      client(fetchImpl).assertCanRegenerateInvite(),
    ).rejects.toBeInstanceOf(SentryWorkspaceCapabilityError);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const firstCall = fetchImpl.mock.calls[0];
    if (firstCall === undefined)
      throw new Error("expected_sentry_auth_request");
    expect(urlOf(firstCall[0])).toBe(`${API}/`);

    const integrationFetch = vi.fn<typeof fetch>(async () =>
      Response.json({ auth: { scopes: ["member:admin"] }, user: null }),
    );
    await expect(
      client(integrationFetch).assertCanRegenerateInvite(),
    ).rejects.toBeInstanceOf(SentryWorkspaceCapabilityError);

    const authorizedFetch = vi.fn<typeof fetch>(async () =>
      Response.json({
        auth: { scopes: ["member:admin"] },
        user: { id: "1001" },
      }),
    );
    await expect(
      client(authorizedFetch).assertCanRegenerateInvite(),
    ).resolves.toBeUndefined();
  });

  it("invokes fetch without using the Sentry client as its receiver", async () => {
    const receivers: unknown[] = [];
    const fetchImpl = async function (
      this: unknown,
      input: RequestInfo | URL,
      _init?: RequestInit,
    ): Promise<Response> {
      receivers.push(this);
      return readSentryState(urlOf(input), {
        organizationMembers: [],
        projectTeams: [{ id: "project-team-1", slug: "platform" }],
        teamMembers: [],
      });
    } as typeof fetch;

    await expect(client(fetchImpl).snapshot()).resolves.toEqual(snapshot());
    expect(receivers).toEqual([undefined, undefined, undefined]);
  });

  it("uses the official list endpoints and exact bearer authentication", async () => {
    const { fetchImpl } = mutableSentryFetch(snapshot());
    await expect(client(fetchImpl).snapshot()).resolves.toEqual(snapshot());
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(
      fetchImpl.mock.calls
        .map(([input]) => urlOf(input))
        .toSorted((left, right) => left.localeCompare(right)),
    ).toEqual(
      [
        `${API}/organizations/example/members/`,
        `${API}/projects/example/platform/teams/`,
        `${API}/teams/example/platform/members/`,
      ].toSorted((left, right) => left.localeCompare(right)),
    );
    for (const [, init] of fetchImpl.mock.calls) {
      expect(new Headers(init?.headers).get("authorization")).toBe(
        "Bearer secret-test-token",
      );
    }
  });

  it("reads the complete organization inventory without requesting a selected detail slice", async () => {
    const existing = member("1", "existing@company.test");
    const invited = member("2", "invited@company.test", { pending: true });
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json([existing], {
          headers: {
            link: '<https://sentry.io/api/0/organizations/example/members/?cursor=next>; rel="next"; results="true"',
          },
        }),
      )
      .mockResolvedValueOnce(Response.json([invited]));
    const result = await client(fetchImpl).listOrganizationMembers();
    expect(
      result.map(({ id, email, pending }) => ({ id, email, pending })),
    ).toEqual([
      { id: "1", email: "existing@company.test", pending: false },
      { id: "2", email: "invited@company.test", pending: true },
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl.mock.calls.map(([input]) => urlOf(input))).toEqual([
      `${API}/organizations/example/members/`,
      `${API}/organizations/example/members/?cursor=next`,
    ]);
  });

  it("rejects duplicate or truncated complete organization inventories", async () => {
    const existing = member("1", "existing@company.test");
    const duplicates = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json([existing, existing]));
    await expect(
      client(duplicates).listOrganizationMembers(),
    ).rejects.toThrow();
    const truncated = vi.fn<typeof fetch>().mockResolvedValue(
      Response.json([existing], {
        headers: {
          link: '<https://sentry.io/api/0/organizations/example/members/?cursor=next>; rel="next"; results="true"',
        },
      }),
    );
    await expect(
      client(truncated, { maxPages: 1 }).listOrganizationMembers(),
    ).rejects.toBeInstanceOf(SentryWorkspaceBoundExceededError);
    expect(truncated).toHaveBeenCalledOnce();
  });

  it("adds a member once and verifies team access", async () => {
    const existing = member("1", "existing@company.test");
    const { fetchImpl } = mutableSentryFetch(
      snapshot({ organizationMembers: [existing] }),
    );
    const sentry = client(fetchImpl);
    const action = {
      email: "existing@company.test",
      memberId: "1",
      type: "add-team-member",
    } as const;

    await applySentryWorkspaceAction(sentry, action);
    await applySentryWorkspaceAction(sentry, action);

    expect(
      fetchImpl.mock.calls.filter(
        ([input, init]) =>
          init?.method === "POST" && urlOf(input).includes("/teams/platform/"),
      ),
    ).toHaveLength(1);
  });

  it("rejects a stale action against a now-privileged Sentry target", async () => {
    const protectedMember = member("1", "protected@company.test", {
      orgRole: "manager",
      role: "manager",
    });
    const { fetchImpl } = mutableSentryFetch(
      snapshot({ organizationMembers: [protectedMember] }),
    );

    await expect(
      applySentryWorkspaceAction(client(fetchImpl), {
        email: "protected@company.test",
        memberId: "1",
        type: "add-team-member",
      }),
    ).rejects.toThrow("sentry_workspace_prewrite_drift");
    expect(
      fetchImpl.mock.calls.some(([, init]) => init?.method === "POST"),
    ).toBe(false);
  });

  it("invites and reinvites with least-privilege bodies and exact readback", async () => {
    const expired = member("2", "expired@company.test", {
      expired: true,
      pending: true,
    });
    const pending = member("3", "pending@company.test", { pending: true });
    const { fetchImpl } = mutableSentryFetch(
      snapshot({ organizationMembers: [expired, pending] }),
    );
    const sentry = client(fetchImpl);

    await applySentryWorkspaceAction(sentry, {
      email: "new@company.test",
      type: "invite",
    });
    await applySentryWorkspaceAction(sentry, {
      email: "expired@company.test",
      memberId: "2",
      type: "reinvite-expired",
    });
    await applySentryWorkspaceAction(sentry, {
      email: "pending@company.test",
      memberId: "3",
      type: "repair-pending-invite",
    });

    const inviteCall = fetchImpl.mock.calls.find(
      ([input, init]) =>
        init?.method === "POST" && urlOf(input).endsWith("/members/"),
    );
    expect(JSON.parse(requestBody(inviteCall?.[1]))).toEqual({
      email: "new@company.test",
      orgRole: "member",
      teamRoles: [{ role: "contributor", teamSlug: "platform" }],
    });
    const reinviteCall = fetchImpl.mock.calls.find(
      ([input, init]) =>
        init?.method === "PUT" &&
        urlOf(input) === `${API}/organizations/example/members/2/`,
    );
    expect(JSON.parse(requestBody(reinviteCall?.[1]))).toEqual({
      regenerate: true,
      reinvite: true,
    });
    expect(
      fetchImpl.mock.calls.some(
        ([input, init]) =>
          init?.method === "POST" &&
          urlOf(input) ===
            `${API}/organizations/example/members/3/teams/platform/`,
      ),
    ).toBe(true);
  });

  it.each([
    {
      action: { email: "new@company.test", type: "invite" } as const,
      initial: snapshot(),
      method: "POST",
      url: `${API}/organizations/example/members/`,
    },
    {
      action: {
        email: "expired@company.test",
        memberId: "expired-id",
        type: "reinvite-expired",
      } as const,
      initial: snapshot({
        organizationMembers: [
          member("expired-id", "expired@company.test", {
            expired: true,
            pending: true,
          }),
        ],
      }),
      method: "PUT",
      url: `${API}/organizations/example/members/expired-id/`,
    },
    {
      action: {
        email: "pending@company.test",
        memberId: "pending-id",
        type: "repair-pending-invite",
      } as const,
      initial: snapshot({
        organizationMembers: [
          member("pending-id", "pending@company.test", { pending: true }),
        ],
      }),
      method: "POST",
      url: `${API}/organizations/example/members/pending-id/teams/platform/`,
    },
  ])(
    "makes $action.type retry idempotent after exact provider convergence",
    async ({ action, initial, method, url }) => {
      const { fetchImpl } = mutableSentryFetch(initial);
      const sentry = client(fetchImpl);
      await applySentryWorkspaceAction(sentry, action);
      await applySentryWorkspaceAction(sentry, action);
      expect(
        fetchImpl.mock.calls.filter(
          ([input, init]) => init?.method === method && urlOf(input) === url,
        ),
      ).toHaveLength(1);
    },
  );

  it.each([
    {
      action: {
        email: "existing@company.test",
        memberId: "existing-id",
        type: "add-team-member",
      } as const,
      initial: snapshot({
        organizationMembers: [member("existing-id", "existing@company.test")],
      }),
    },
    {
      action: { email: "new@company.test", type: "invite" } as const,
      initial: snapshot(),
    },
    {
      action: {
        email: "expired@company.test",
        memberId: "expired-id",
        type: "reinvite-expired",
      } as const,
      initial: snapshot({
        organizationMembers: [
          member("expired-id", "expired@company.test", {
            expired: true,
            pending: true,
          }),
        ],
      }),
    },
    {
      action: {
        email: "pending@company.test",
        memberId: "pending-id",
        type: "repair-pending-invite",
      } as const,
      initial: snapshot({
        organizationMembers: [
          member("pending-id", "pending@company.test", { pending: true }),
        ],
      }),
    },
  ])(
    "requires final write authority for $action.type",
    async ({ action, initial }) => {
      const { fetchImpl } = mutableSentryFetch(initial);
      const assertWriteAuthority = vi.fn(async () => {
        throw new Error("final_authority_changed");
      });

      await expect(
        applySentryWorkspaceActionWithAuthority(
          client(fetchImpl),
          action,
          assertWriteAuthority,
        ),
      ).rejects.toThrow("final_authority_changed");

      expect(assertWriteAuthority).toHaveBeenCalledOnce();
      expect(
        fetchImpl.mock.calls.filter(([, init]) => init?.method !== "GET"),
      ).toHaveLength(0);
    },
  );

  it("blocks stale invite operations before any provider write", async () => {
    const cases: {
      action: SentryWorkspaceAction;
      initial: SentryWorkspaceSnapshot;
    }[] = [
      {
        action: { email: "existing@company.test", type: "invite" },
        initial: snapshot({
          organizationMembers: [member("1", "existing@company.test")],
        }),
      },
      {
        action: {
          email: "expired@company.test",
          memberId: "wrong-id",
          type: "reinvite-expired",
        },
        initial: snapshot({
          organizationMembers: [
            member("actual-id", "expired@company.test", {
              expired: true,
              pending: true,
            }),
          ],
        }),
      },
      {
        action: {
          email: "accepted-expired@company.test",
          memberId: "accepted-expired-id",
          type: "reinvite-expired",
        },
        initial: snapshot({
          organizationMembers: [
            member("accepted-expired-id", "accepted-expired@company.test", {
              expired: true,
            }),
          ],
        }),
      },
      {
        action: {
          email: "pending-wrong-id@company.test",
          memberId: "wrong-id",
          type: "repair-pending-invite",
        },
        initial: snapshot({
          organizationMembers: [
            member("actual-id", "pending-wrong-id@company.test", {
              pending: true,
            }),
          ],
        }),
      },
      {
        action: {
          email: "accepted@company.test",
          memberId: "accepted-id",
          type: "repair-pending-invite",
        },
        initial: snapshot({
          organizationMembers: [member("accepted-id", "accepted@company.test")],
        }),
      },
      {
        action: {
          email: "pending@company.test",
          memberId: "pending-id",
          type: "repair-pending-invite",
        },
        initial: snapshot({
          organizationMembers: [
            member("pending-id", "pending@company.test", {
              expired: true,
              pending: true,
            }),
          ],
        }),
      },
    ];

    await Promise.all(
      cases.map(async ({ action, initial }) => {
        const { fetchImpl } = mutableSentryFetch(initial);
        await expect(
          applySentryWorkspaceAction(client(fetchImpl), action),
        ).rejects.toThrow("sentry_workspace_prewrite_drift");
        expect(
          fetchImpl.mock.calls.filter(([, init]) => init?.method !== "GET"),
        ).toHaveLength(0);
      }),
    );
  });

  it("treats an already renewed exact pending invite as a zero-write converged retry", async () => {
    const { fetchImpl } = mutableSentryFetch(
      snapshot({
        organizationMembers: [
          member("renewed-id", "renewed@company.test", {
            expired: false,
            pending: true,
          }),
        ],
      }),
    );
    await expect(
      applySentryWorkspaceAction(client(fetchImpl), {
        email: "renewed@company.test",
        memberId: "renewed-id",
        type: "reinvite-expired",
      }),
    ).resolves.toBeUndefined();
    expect(
      fetchImpl.mock.calls.filter(([, init]) => init?.method !== "GET"),
    ).toHaveLength(0);
  });

  it("fails closed on excessive or mismatched pending-member detail reads", async () => {
    const unusedFetch = vi.fn<typeof fetch>();
    await expect(
      client(unusedFetch).snapshot(
        Array.from(
          { length: 51 },
          (_, index) => `member-${String(index)}@company.test`,
        ),
      ),
    ).rejects.toThrow("sentry_workspace_member-detail_bound_exceeded");
    expect(unusedFetch).not.toHaveBeenCalled();

    const excessivePending = Array.from({ length: 26 }, (_, index) =>
      member(
        `pending-${String(index)}`,
        `pending-${String(index)}@company.test`,
        {
          pending: true,
        },
      ),
    );
    const excessiveState: MutableSentryState = {
      organizationMembers: excessivePending,
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const excessiveFetch = vi.fn(async (input: RequestInfo | URL) =>
      readSentryState(urlOf(input), excessiveState),
    );
    await expect(
      client(excessiveFetch).snapshot(
        excessivePending.map(({ email }) => email),
      ),
    ).rejects.toThrow("sentry_workspace_member-detail_bound_exceeded");
    expect(
      excessiveFetch.mock.calls.filter(([input]) =>
        /\/organizations\/example\/members\/pending-\d+\/$/u.test(urlOf(input)),
      ),
    ).toHaveLength(0);

    const pending = member("pending-id", "pending@company.test", {
      pending: true,
    });
    const state: MutableSentryState = {
      organizationMembers: [pending],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const mismatchedFetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = urlOf(input);
      if (url === `${API}/organizations/example/members/pending-id/`) {
        return Response.json({
          ...pending,
          id: "different-id",
          teamRoles: [],
          teams: [],
        });
      }
      return readSentryState(url, state);
    });
    await expect(
      client(mismatchedFetch).snapshot(["pending@company.test"]),
    ).rejects.toThrow("sentry_workspace_member_detail_mismatch");

    const emailMismatchFetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = urlOf(input);
      if (url === `${API}/organizations/example/members/pending-id/`) {
        return Response.json({
          ...pending,
          email: "different@company.test",
          teamRoles: [],
          teams: [],
          user: { email: "different@company.test" },
        });
      }
      return readSentryState(url, state);
    });
    await expect(
      client(emailMismatchFetch).snapshot(["pending@company.test"]),
    ).rejects.toThrow("sentry_workspace_member_detail_mismatch");
  });

  it("rejects duplicate provider summary identities before selecting detail targets", async () => {
    const state: MutableSentryState = {
      organizationMembers: [
        member("shared-id", "target@company.test"),
        member("shared-id", "unrelated@company.test"),
      ],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) =>
        readSentryState(urlOf(input), state),
    );

    await expect(
      client(fetchImpl).snapshot(["target@company.test"]),
    ).rejects.toThrow("sentry_workspace_member_summary_ambiguous");
    expect(
      fetchImpl.mock.calls.some(([, init]) => init?.method !== "GET"),
    ).toBe(false);
    expect(
      fetchImpl.mock.calls.some(([input]) =>
        urlOf(input).endsWith("/organizations/example/members/shared-id/"),
      ),
    ).toBe(false);
  });

  it("fails closed when any provider member summary has no matchable email identity", async () => {
    const state: MutableSentryState = {
      organizationMembers: [
        member("target-id", "target@company.test"),
        {
          ...member("opaque-id", "opaque@company.test"),
          email: null,
          user: null,
        },
      ],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      readSentryState(urlOf(input), state),
    );

    await expect(
      client(fetchImpl).snapshot(["target@company.test"]),
    ).rejects.toThrow("sentry_workspace_member_summary_ambiguous");
    expect(
      fetchImpl.mock.calls.some(([input]) =>
        urlOf(input).endsWith("/organizations/example/members/target-id/"),
      ),
    ).toBe(false);
  });

  it("never treats a listed eligible identity with unavailable detail as an invite candidate", async () => {
    const target = member("target-id", "target@company.test");
    const state: MutableSentryState = {
      organizationMembers: [target],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) => {
        const url = urlOf(input);
        if (url === `${API}/organizations/example/members/target-id/`) {
          return new Response(null, { status: 404 });
        }
        return readSentryState(url, state);
      },
    );

    await expect(
      auditSentryWorkspaceSync(["target@company.test"], client(fetchImpl)),
    ).rejects.toThrow("sentry_workspace_request_failed:404");
    expect(
      fetchImpl.mock.calls.some(([, init]) => init?.method !== "GET"),
    ).toBe(false);
  });

  it("rejects an unknown detailed member role without any provider write", async () => {
    const target = member("target-id", "target@company.test");
    const state: MutableSentryState = {
      organizationMembers: [target],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) => {
        const url = urlOf(input);
        if (url === `${API}/organizations/example/members/target-id/`) {
          return Response.json({ ...target, role: "superuser" });
        }
        return readSentryState(url, state);
      },
    );

    await expect(
      auditSentryWorkspaceSync(["target@company.test"], client(fetchImpl)),
    ).rejects.toThrow();
    expect(
      fetchImpl.mock.calls.some(([, init]) => init?.method !== "GET"),
    ).toBe(false);
  });

  it("loads strict details only for requested candidate identities", async () => {
    const target = member("target-id", "target@company.test", {
      pending: true,
      teams: ["platform"],
    });
    const unrelated = member("unrelated-id", "unrelated@company.test", {
      pending: true,
    });
    const active = member("active-id", "active@company.test");
    const expired = member("expired-id", "expired@company.test", {
      expired: true,
      pending: true,
    });
    const state: MutableSentryState = {
      organizationMembers: [target, unrelated, active, expired],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      readSentryState(urlOf(input), state),
    );

    const result = await client(fetchImpl).snapshot([
      "target@company.test",
      "active@company.test",
      "expired@company.test",
    ]);
    expect(
      result.organizationMembers.find(({ id }) => id === "target-id")?.teams,
    ).toEqual(["platform"]);
    expect(
      fetchImpl.mock.calls
        .map(([input]) => urlOf(input))
        .filter((url) =>
          /\/organizations\/example\/members\/[^/]+\/$/u.test(url),
        ),
    ).toEqual([
      `${API}/organizations/example/members/target-id/`,
      `${API}/organizations/example/members/active-id/`,
      `${API}/organizations/example/members/expired-id/`,
    ]);
  });

  it("bounds pending-member detail concurrency at four", async () => {
    const members = Array.from({ length: 5 }, (_, index) =>
      member(
        `pending-${String(index)}`,
        `pending-${String(index)}@company.test`,
        {
          pending: true,
        },
      ),
    );
    const releases: (() => void)[] = [];
    let inFlight = 0;
    let maxInFlight = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = urlOf(input);
      const detailMatch =
        /\/organizations\/example\/members\/(pending-\d+)\/$/u.exec(url);
      if (detailMatch?.[1] !== undefined) {
        const selected = members.find(({ id }) => id === detailMatch[1]);
        if (selected === undefined) return new Response(null, { status: 404 });
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise<void>((resolve) => {
          releases.push(resolve);
        });
        inFlight -= 1;
        return Response.json({ ...selected, teamRoles: [], teams: [] });
      }
      return readSentryState(url, {
        organizationMembers: members,
        projectTeams: [{ id: "project-team-1", slug: "platform" }],
        teamMembers: [],
      });
    });

    const snapshotPromise = client(fetchImpl).snapshot(
      members.map(({ email }) => email),
    );
    await vi.waitFor(() => expect(releases).toHaveLength(4));
    expect(maxInFlight).toBe(4);
    expect(
      fetchImpl.mock.calls.filter(([input]) =>
        /\/organizations\/example\/members\/pending-\d+\/$/u.test(urlOf(input)),
      ),
    ).toHaveLength(4);
    for (const release of releases) release();
    releases.length = 0;
    await vi.waitFor(() => expect(releases).toHaveLength(1));
    for (const release of releases) release();
    releases.length = 0;
    await expect(snapshotPromise).resolves.toBeDefined();
    expect(maxInFlight).toBe(4);
  });

  it("pins apply to the exact audited plan hash", async () => {
    const current = snapshot({
      organizationMembers: [member("1", "existing@company.test")],
    });
    const { fetchImpl } = mutableSentryFetch(current);
    const sentry = client(fetchImpl);
    const audited = await auditSentryWorkspaceSync(
      ["existing@company.test"],
      sentry,
    );
    expect(audited.planHash).toMatch(/^[a-f0-9]{64}$/u);
    const [action] = audited.actions;
    if (action === undefined) throw new Error("expected_audited_action");
    await applySentryWorkspacePlanAction(
      ["existing@company.test"],
      sentry,
      action,
      audited.planHash,
    );
    await expect(
      applySentryWorkspacePlanAction(
        ["existing@company.test"],
        sentry,
        action,
        audited.planHash,
      ),
    ).rejects.toThrow("sentry_workspace_prewrite_drift");
  });

  it("fails when mutation readback does not prove convergence", async () => {
    const current = snapshot({
      organizationMembers: [member("1", "existing@company.test")],
    });
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if ((init?.method ?? "GET") !== "GET")
          return Response.json({}, { status: 201 });
        return readSentryState(urlOf(input), {
          organizationMembers: [...current.organizationMembers],
          projectTeams: [...current.projectTeams],
          teamMembers: [...current.teamMembers],
        });
      },
    );
    await expect(
      applySentryWorkspaceAction(client(fetchImpl), {
        email: "existing@company.test",
        memberId: "1",
        type: "add-team-member",
      }),
    ).rejects.toBeInstanceOf(SentryWorkspaceReadbackError);
  });

  it.each([
    {
      action: { email: "new@company.test", type: "invite" } as const,
      initial: [],
    },
    {
      action: {
        email: "pending@company.test",
        memberId: "pending-id",
        type: "repair-pending-invite",
      } as const,
      initial: [
        member("pending-id", "pending@company.test", { pending: true }),
      ],
    },
  ])(
    "rejects $action.type readback without exact platform-team membership",
    async ({ action, initial }) => {
      const state: MutableSentryState = {
        organizationMembers: structuredClone(initial),
        projectTeams: [{ id: "project-team-1", slug: "platform" }],
        teamMembers: [],
      };
      const fetchImpl = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = urlOf(input);
          if ((init?.method ?? "GET") === "GET")
            return readSentryState(url, state);
          if (action.type === "invite") {
            state.organizationMembers.push(
              member("new-id", action.email, { pending: true }),
            );
          } else {
            const existing = state.organizationMembers.find(
              ({ id }) => id === action.memberId,
            );
            if (existing !== undefined) existing.expired = false;
          }
          return Response.json({}, { status: 201 });
        },
      );

      await expect(
        applySentryWorkspaceAction(client(fetchImpl), action),
      ).rejects.toBeInstanceOf(SentryWorkspaceReadbackError);
      expect(state.teamMembers).toEqual([]);
    },
  );

  it.each([
    {
      action: { email: "new-active@company.test", type: "invite" } as const,
      initial: [] as MutableSentryState["organizationMembers"],
      mutate: (state: MutableSentryState) => {
        const changed = member("new-id", "new-active@company.test", {
          teams: ["platform"],
        });
        state.organizationMembers.push(changed);
        state.teamMembers.push(changed);
      },
      status: 201,
    },
    {
      action: { email: "new-expired@company.test", type: "invite" } as const,
      initial: [] as MutableSentryState["organizationMembers"],
      mutate: (state: MutableSentryState) => {
        state.organizationMembers.push(
          member("new-id", "new-expired@company.test", {
            expired: true,
            pending: true,
            teams: ["platform"],
          }),
        );
      },
      status: 201,
    },
    {
      action: {
        email: "reinvite-active@company.test",
        memberId: "member-id",
        type: "reinvite-expired",
      } as const,
      initial: [
        member("member-id", "reinvite-active@company.test", {
          expired: true,
          pending: true,
        }),
      ],
      mutate: (state: MutableSentryState) => {
        state.organizationMembers[0] = member(
          "member-id",
          "reinvite-active@company.test",
        );
      },
      status: 200,
    },
    {
      action: {
        email: "reinvite-changed@company.test",
        memberId: "member-id",
        type: "reinvite-expired",
      } as const,
      initial: [
        member("member-id", "reinvite-changed@company.test", {
          expired: true,
          pending: true,
        }),
      ],
      mutate: (state: MutableSentryState) => {
        state.organizationMembers[0] = member(
          "changed-id",
          "reinvite-changed@company.test",
          {
            pending: true,
          },
        );
      },
      status: 200,
    },
    {
      action: {
        email: "repair-active@company.test",
        memberId: "member-id",
        type: "repair-pending-invite",
      } as const,
      initial: [
        member("member-id", "repair-active@company.test", { pending: true }),
      ],
      mutate: (state: MutableSentryState) => {
        const changed = member("member-id", "repair-active@company.test", {
          teams: ["platform"],
        });
        state.organizationMembers[0] = changed;
        state.teamMembers.push(changed);
      },
      status: 201,
    },
    {
      action: {
        email: "repair-expired@company.test",
        memberId: "member-id",
        type: "repair-pending-invite",
      } as const,
      initial: [
        member("member-id", "repair-expired@company.test", { pending: true }),
      ],
      mutate: (state: MutableSentryState) => {
        state.organizationMembers[0] = member(
          "member-id",
          "repair-expired@company.test",
          {
            expired: true,
            pending: true,
            teams: ["platform"],
          },
        );
      },
      status: 201,
    },
    {
      action: {
        email: "repair-changed@company.test",
        memberId: "member-id",
        type: "repair-pending-invite",
      } as const,
      initial: [
        member("member-id", "repair-changed@company.test", { pending: true }),
      ],
      mutate: (state: MutableSentryState) => {
        state.organizationMembers[0] = member(
          "changed-id",
          "repair-changed@company.test",
          {
            pending: true,
            teams: ["platform"],
          },
        );
      },
      status: 201,
    },
  ])(
    "rejects $action.type readback when one identity-state predicate is wrong",
    async ({ action, initial, mutate, status }) => {
      const state: MutableSentryState = {
        organizationMembers: structuredClone(initial),
        projectTeams: [{ id: "project-team-1", slug: "platform" }],
        teamMembers: [],
      };
      const fetchImpl = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          if ((init?.method ?? "GET") === "GET")
            return readSentryState(urlOf(input), state);
          mutate(state);
          return Response.json({}, { status });
        },
      );

      await expect(
        applySentryWorkspaceAction(client(fetchImpl), action),
      ).rejects.toThrow(`sentry_workspace_readback_failed:${action.type}`);
      expect(
        fetchImpl.mock.calls.filter(([, init]) => init?.method !== "GET"),
      ).toHaveLength(1);
    },
  );

  it("treats a successful reinvite as separate from pending team repair", async () => {
    const expired = member("expired-id", "expired@company.test", {
      expired: true,
      pending: true,
      teams: ["example"],
    });
    const { fetchImpl } = mutableSentryFetch(
      snapshot({ organizationMembers: [expired] }),
    );
    const sentry = client(fetchImpl);
    await expect(
      applySentryWorkspaceAction(sentry, {
        email: "expired@company.test",
        memberId: "expired-id",
        type: "reinvite-expired",
      }),
    ).resolves.toBeUndefined();

    await expect(
      auditSentryWorkspaceSync(["expired@company.test"], sentry),
    ).resolves.toMatchObject({
      actions: [
        {
          email: "expired@company.test",
          memberId: "expired-id",
          type: "repair-pending-invite",
        },
      ],
    });
  });

  it("rejects reinvite readback when the exact invite remains expired", async () => {
    const expired = member("expired-id", "expired@company.test", {
      expired: true,
      pending: true,
    });
    const state: MutableSentryState = {
      organizationMembers: [expired],
      projectTeams: [{ id: "project-team-1", slug: "platform" }],
      teamMembers: [],
    };
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "PUT") return Response.json(expired);
        return readSentryState(urlOf(input), state);
      },
    );
    await expect(
      applySentryWorkspaceAction(client(fetchImpl), {
        email: "expired@company.test",
        memberId: "expired-id",
        type: "reinvite-expired",
      }),
    ).rejects.toThrow("sentry_workspace_readback_failed:reinvite-expired");
    expect(
      fetchImpl.mock.calls.filter(([, init]) => init?.method === "PUT"),
    ).toHaveLength(1);
  });

  it("bounds pagination and never includes the token in provider errors", async () => {
    const paginated = vi.fn(async (input: RequestInfo | URL) => {
      const next = new URL(urlOf(input));
      next.searchParams.set("cursor", "next");
      return Response.json([], {
        headers: {
          link: `<${next.toString()}>; rel="next"; results="true"`,
        },
      });
    });
    await expect(
      client(paginated, { maxPages: 1 }).snapshot(),
    ).rejects.toBeInstanceOf(SentryWorkspaceBoundExceededError);

    const denied = client(
      vi.fn(async () => new Response(null, { status: 403 })),
    );
    const error = await denied.snapshot().catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(SentryWorkspaceRequestError);
    expect(String(error)).not.toContain("secret-test-token");
  });

  it("never follows a provider pagination link outside the pinned Sentry API origin", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      Response.json([], {
        headers: {
          link: '<https://attacker.example/collect>; rel="next"; results="true"',
        },
      }),
    );
    await expect(client(fetchImpl).snapshot()).rejects.toThrow(
      "sentry_workspace_untrusted_pagination_url",
    );
    expect(
      fetchImpl.mock.calls.every(([input]) => urlOf(input).startsWith(API)),
    ).toBe(true);
  });

  it.each([
    "https://sentry.io/api/0/organizations/other/members/?cursor=next",
    "https://sentry.io/api/0/organizations/example/projects/?cursor=next",
  ])(
    "never follows pagination outside the original provider collection: %s",
    async (nextUrl) => {
      const fetchImpl = vi.fn<typeof fetch>(async (input) => {
        const url = urlOf(input);
        if (url === `${API}/organizations/example/members/`) {
          return Response.json([], {
            headers: { link: `<${nextUrl}>; rel="next"; results="true"` },
          });
        }
        return Response.json([]);
      });

      await expect(client(fetchImpl).snapshot()).rejects.toThrow(
        "sentry_workspace_untrusted_pagination_url",
      );
      expect(
        fetchImpl.mock.calls.some(([input]) => urlOf(input) === nextUrl),
      ).toBe(false);
    },
  );

  it.each([
    {
      action: { email: "new@company.test", type: "invite" } as const,
      initial: snapshot(),
      method: "POST",
      url: `${API}/organizations/example/members/`,
    },
    {
      action: {
        email: "expired@company.test",
        memberId: "expired-id",
        type: "reinvite-expired",
      } as const,
      initial: snapshot({
        organizationMembers: [
          member("expired-id", "expired@company.test", {
            expired: true,
            pending: true,
          }),
        ],
      }),
      method: "PUT",
      url: `${API}/organizations/example/members/expired-id/`,
    },
  ])(
    "rejects async-accepted $action.type mutations as non-final",
    async ({ action, initial, method, url }) => {
      const state: MutableSentryState = {
        organizationMembers: [...initial.organizationMembers],
        projectTeams: [...initial.projectTeams],
        teamMembers: [...initial.teamMembers],
      };
      const fetchImpl = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          if ((init?.method ?? "GET") === "GET")
            return readSentryState(urlOf(input), state);
          return Response.json({}, { status: 202 });
        },
      );

      await expect(
        applySentryWorkspaceAction(client(fetchImpl), action),
      ).rejects.toBeInstanceOf(SentryWorkspaceUnexpectedMutationStatusError);
      expect(
        fetchImpl.mock.calls.filter(
          ([input, init]) => init?.method === method && urlOf(input) === url,
        ),
      ).toHaveLength(1);
    },
  );

  it("rejects Sentry async-accepted team additions because readback is not final", async () => {
    const existing = member("1", "existing@company.test");
    const state = snapshot({ organizationMembers: [existing] });
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === "POST") return Response.json({}, { status: 202 });
        return readSentryState(urlOf(input), {
          organizationMembers: [...state.organizationMembers],
          projectTeams: [...state.projectTeams],
          teamMembers: [...state.teamMembers],
        });
      },
    );
    await expect(
      applySentryWorkspaceAction(client(fetchImpl), {
        email: "existing@company.test",
        memberId: "1",
        type: "add-team-member",
      }),
    ).rejects.toBeInstanceOf(SentryWorkspaceUnexpectedMutationStatusError);
  });
});

describe("Sentry organization removal transport", () => {
  it("sends exactly one scoped DELETE after the final authority callback", async () => {
    const events: string[] = [];
    const transport = vi.fn<typeof fetch>(async (url, init) => {
      events.push("delete");
      expect(urlOf(url)).toBe(`${API}/organizations/example/members/5001/`);
      expect(init).toMatchObject({ method: "DELETE", redirect: "manual" });
      expect(init?.body).toBeUndefined();
      return new Response(null, { status: 204 });
    });
    await client(transport).removeOrganizationMember("5001", async () => {
      events.push("authority");
    });
    expect(events).toEqual(["authority", "delete"]);
    expect(transport).toHaveBeenCalledOnce();
  });

  it("never sends DELETE after a rejected fence or malformed member ID", async () => {
    const transport = vi.fn<typeof fetch>();
    await expect(
      client(transport).removeOrganizationMember("5001", async () => {
        throw new Error("revoked");
      }),
    ).rejects.toThrow("revoked");
    await expect(
      client(transport).removeOrganizationMember("../me", allowWrite),
    ).rejects.toThrow();
    expect(transport).not.toHaveBeenCalled();
  });

  it("never retries an ambiguous DELETE or a retryable provider failure", async () => {
    for (const response of [
      async () => {
        throw new Error("timeout");
      },
      async () => new Response(null, { status: 503 }),
    ]) {
      const transport = vi.fn<typeof fetch>(response);
      await expect(
        client(transport, { readMaxAttempts: 3 }).removeOrganizationMember(
          "5001",
          allowWrite,
        ),
      ).rejects.toThrow();
      expect(transport).toHaveBeenCalledOnce();
    }
  });
});
