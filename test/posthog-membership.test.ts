import { describe, expect, it, vi } from "vitest";

import { GoogleUserIdSchema } from "../src/catalog/identity-authority.ts";
import {
  PosthogMembershipService,
  type PosthogMembershipParent,
} from "../src/execution/posthog-membership-service.ts";
import { ReviewedPosthogMembershipSchema } from "../src/execution/reviewed-posthog-membership.ts";
import { buildEmployeeEntitlementAuthority } from "../src/identity-provisioning/employee-entitlement-policy.ts";
import {
  activeResourceLease,
  type ResourceLeaseRepository,
} from "../src/identity-sync/resource-lease.ts";
import type { GoogleGroupSnapshot } from "../src/org-sync/channel-model.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import { PosthogInvitationIdSchema } from "../src/workspace-directory/posthog-managed-grant.ts";
import {
  PosthogMembershipClient,
  type IPosthogMembershipClient,
  type PosthogMembershipSnapshot,
} from "../src/workspace-directory/posthog-membership-client.ts";
import {
  planPosthogMemberships,
  PosthogManagedGrantSchema,
  PosthogMembershipPolicySchema,
  type PosthogManagedGrant,
} from "../src/workspace-directory/posthog-membership-plan.ts";

const org = "00000000-0000-0000-0000-000000000001";
const actor = "00000000-0000-0000-0000-000000000002";
const target = "00000000-0000-0000-0000-000000000003";
const inviteId = "00000000-0000-0000-0000-000000000004";
const memberRecordId = "00000000-0000-0000-0000-000000000005";
const policy = PosthogMembershipPolicySchema.parse({
  origin: "https://us.posthog.com",
  organizationId: org,
  actorUuid: actor,
  authorityGroupEmail: "team-product@company.test",
  authorityGroupId: "product-test",
  minimumGoogleUsers: 2,
});
const people: GoogleDirectoryUser[] = [
  { id: "111111", primaryEmail: "owner@company.test" },
  { id: "222222", primaryEmail: "product@company.test" },
];
function snapshot(): PosthogMembershipSnapshot {
  return {
    organizationId: org,
    actorUuid: actor,
    members: [
      {
        id: actor,
        level: 15,
        user: { uuid: actor, email: "owner@company.test" },
      },
    ],
    invites: [],
  };
}
function grant(
  overrides: Partial<PosthogManagedGrant> = {},
): PosthogManagedGrant {
  return PosthogManagedGrantSchema.parse({
    googleUserId: GoogleUserIdSchema.parse("222222"),
    email: "product@company.test",
    evidence: { kind: "membership", userUuid: target },
    state: "managed",
    ...overrides,
  });
}
async function fixture(mode: "parent" | "audit-only" = "parent") {
  const users = structuredClone(people);
  const groups: GoogleGroupSnapshot[] = [
    {
      id: "product-test",
      email: policy.authorityGroupEmail,
      members: users.map((u) => ({
        id: u.id,
        email: u.primaryEmail,
        type: "USER",
        role: "MEMBER",
        status: "ACTIVE",
      })),
    },
  ];
  const providerState = snapshot();
  const records = new Map<string, PosthogManagedGrant>();
  const provider = {
    read: vi.fn(() => Promise.resolve(structuredClone(providerState))),
    invite: vi.fn((email) => {
      const invite = {
        id: inviteId,
        "target_email": email,
        level: 1,
        "is_expired": false,
        "created_by": { uuid: actor },
      };
      providerState.invites.push(invite);
      return Promise.resolve(invite);
    }),
    cancelInvite: vi.fn((id) => {
      providerState.invites = providerState.invites.filter((i) => i.id !== id);
      return Promise.resolve();
    }),
    removeMember: vi.fn((id) => {
      providerState.members = providerState.members.filter(
        (m) => m.user.uuid !== id,
      );
      return Promise.resolve();
    }),
  } satisfies IPosthogMembershipClient;
  const leases: ResourceLeaseRepository = {
    acquire: vi.fn<ResourceLeaseRepository["acquire"]>((resourceKey) =>
      Promise.resolve({
        kind: "acquired",
        lease: activeResourceLease({
          resourceKey,
          ownerId: "00000000-0000-4000-8000-000000000001",
          generation: 1,
          expiresAtMs: Date.now() + 600_000,
        }),
      }),
    ),
    assertActive: vi.fn(() => Promise.resolve()),
    release: vi.fn(() => Promise.resolve()),
  };
  const builtAuthority = await buildEmployeeEntitlementAuthority({
    id: "contractor-group-test",
    email: "team-contractors@company.test",
    members: [],
  });
  const authority = {
    ...builtAuthority,
    excludedGoogleUserIds: [...builtAuthority.excludedGoogleUserIds],
    excludedEmails: [...builtAuthority.excludedEmails],
  };
  const service = new PosthogMembershipService(
    policy,
    {
      directory: {
        listAllUsers: () => Promise.resolve(structuredClone(users)),
      },
      groups: { listGroups: () => Promise.resolve(structuredClone(groups)) },
      employeeAuthority: () => Promise.resolve(authority),
      provider,
      leases,
      grants: {
        list: () => Promise.resolve(records.values().toArray()),
        record: (_org, row) => {
          records.set(row.googleUserId, row);
          return Promise.resolve();
        },
      },
    },
    mode,
  );
  const parent = {
    mode: "parent",
    identityBudget: { required: true, reserve: vi.fn(() => Promise.resolve()) },
    assertFreshPlan: vi.fn(),
    assertWriteAuthority: vi.fn(() => Promise.resolve()),
    assertFinalSourceAuthority: vi.fn(() => Promise.resolve()),
    verifyPreannouncement: vi.fn(() => Promise.resolve()),
  } satisfies PosthogMembershipParent;
  async function reviewed() {
    const audit = await service.capture();
    return ReviewedPosthogMembershipSchema.parse({
      action: audit.plan.actions[0],
      expectedPlanHash: audit.plan.planHash,
      sourceAuthorityFingerprint: audit.sourceAuthorityFingerprint,
      organizationId: org,
    });
  }
  return {
    users,
    groups,
    providerState,
    provider,
    records,
    leases,
    authority,
    service,
    parent,
    reviewed,
  };
}

describe("PostHog owned membership reconciliation", () => {
  it("invites exactly one Member, verifies it, and converges without duplicates", async () => {
    const f = await fixture();
    const reviewed = await f.reviewed();
    await expect(f.service.applyReviewed(reviewed, f.parent)).resolves.toBe(
      "completed",
    );
    expect(f.provider.invite).toHaveBeenCalledExactlyOnceWith(
      "product@company.test",
    );
    expect(f.parent.identityBudget.reserve).toHaveBeenCalledOnce();
    const observed1 = await f.service.capture();
    expect(observed1.plan.actions).toEqual([]);
    await f.service.applyReviewed(reviewed, f.parent);
    expect(f.provider.invite).toHaveBeenCalledOnce();
  });
  it("binds an accepted invitation before an owned Member can be removed", async () => {
    const f = await fixture();
    await f.service.applyReviewed(await f.reviewed(), f.parent);
    f.providerState.invites = [];
    f.providerState.members.push({
      id: memberRecordId,
      level: 1,
      user: { uuid: target, email: "product@company.test" },
    });
    const observed2 = await f.reviewed();
    expect(observed2.action.type).toBe("bind-member");
    await f.service.applyReviewed(await f.reviewed(), f.parent);
    const group = f.groups[0];
    if (!group) throw new Error("fixture_group_missing");
    group.members = group.members.filter((m) => m.id !== "222222");
    const removal = await f.reviewed();
    expect(removal.action).toMatchObject({
      type: "remove-member",
      userUuid: target,
    });
    await f.service.applyReviewed(removal, f.parent);
    expect(f.provider.removeMember).toHaveBeenCalledExactlyOnceWith(target);
    expect(f.records.get("222222")?.state).toBe("retired");
    f.providerState.members.push({
      id: memberRecordId,
      level: 1,
      user: { uuid: target, email: "product@company.test" },
    });
    const observed3 = await f.service.capture();
    expect(observed3.plan.actions).toEqual([]);
  });
  it("requires review if an unbound accepted Member leaves the group", async () => {
    const f = await fixture();
    f.records.set(
      "222222",
      grant({
        evidence: {
          kind: "invitation",
          inviteId: PosthogInvitationIdSchema.parse(inviteId),
        },
      }),
    );
    f.providerState.members.push({
      id: memberRecordId,
      level: 1,
      user: { uuid: target, email: "product@company.test" },
    });
    const group = f.groups[0];
    if (!group) throw new Error("fixture_group_missing");
    group.members = group.members.filter((m) => m.id !== "222222");
    const observed4 = await f.service.capture();
    expect(observed4.plan.blockers).toContain(
      "posthog_unbound_member_requires_review",
    );
  });
  it("preserves foreign memberships and elevated roles", async () => {
    const f = await fixture();
    f.providerState.members.push({
      id: memberRecordId,
      level: 8,
      user: { uuid: target, email: "product@company.test" },
    });
    const observed5 = await f.service.capture();
    expect(observed5.plan.actions).toEqual([]);
    f.records.set("222222", grant());
    const group = f.groups[0];
    if (!group) throw new Error("fixture_group_missing");
    group.members = group.members.filter((m) => m.id !== "222222");
    const observed6 = await f.service.capture();
    expect(observed6.plan.blockers).toContain(
      "posthog_managed_role_requires_review",
    );
    expect(f.provider.removeMember).not.toHaveBeenCalled();
  });
  it("rejects audit-only execution and a missing required identity budget", async () => {
    const f = await fixture("audit-only");
    await expect(
      f.service.applyReviewed(await f.reviewed(), f.parent),
    ).rejects.toThrow("posthog_signed_parent_required");
    const writable = await fixture();
    await expect(
      writable.service.applyReviewed(await writable.reviewed(), {
        ...writable.parent,
        identityBudget: { required: false },
      }),
    ).rejects.toThrow("posthog_signed_parent_required");
    expect(f.provider.invite).not.toHaveBeenCalled();
    expect(writable.provider.invite).not.toHaveBeenCalled();
  });
  it("rejects a retargeted original action and final Google source drift before writing", async () => {
    const f = await fixture();
    const reviewed = await f.reviewed();
    await expect(
      f.service.applyReviewed(
        {
          ...reviewed,
          action: { ...reviewed.action, email: "other@company.test" },
        },
        f.parent,
      ),
    ).rejects.toThrow("posthog_reviewed_plan_drifted");
    f.parent.assertFinalSourceAuthority.mockImplementation(() => {
      const group = f.groups[0];
      if (group) group.members = group.members.filter((m) => m.id !== "222222");
      return Promise.resolve();
    });
    await expect(f.service.applyReviewed(reviewed, f.parent)).rejects.toThrow(
      "posthog_reviewed_plan_drifted",
    );
    expect(f.provider.invite).not.toHaveBeenCalled();
  });
  it("does not retire ownership when the provider acknowledges but fails to remove a member", async () => {
    const f = await fixture();
    f.records.set("222222", grant());
    f.providerState.members.push({
      id: memberRecordId,
      level: 1,
      user: { uuid: target, email: "product@company.test" },
    });
    const group = f.groups[0];
    if (group) group.members = group.members.filter((m) => m.id !== "222222");
    vi.mocked(f.provider.removeMember).mockResolvedValue();
    await expect(
      f.service.applyReviewed(await f.reviewed(), f.parent),
    ).rejects.toThrow("posthog_membership_readback_failed");
    expect(f.records.get("222222")?.state).toBe("managed");
  });
  it("fails closed on incomplete contractor authority, a changed group ID, and insufficient directory size", async () => {
    const f = await fixture();
    f.authority.complete = false;
    await expect(f.service.capture()).rejects.toThrow(
      "posthog_employee_authority_incomplete",
    );
    f.authority.complete = true;
    const group = f.groups[0];
    if (group) group.id = "different";
    await expect(f.service.capture()).rejects.toThrow(
      "posthog_google_group_authority_mismatch",
    );
    f.users.pop();
    await expect(f.service.capture()).rejects.toThrow(
      "posthog_employee_authority_incomplete",
    );
  });
  it("blocks reused Google aliases and changed provider identities", async () => {
    const f = await fixture();
    f.records.set("222222", grant());
    f.users.push({
      id: "333333",
      primaryEmail: "third@company.test",
      aliases: ["product@company.test"],
    });
    const observed7 = await f.service.capture();
    expect(observed7.plan.blockers).toContain(
      "posthog_managed_identity_changed",
    );
    f.users.pop();
    f.providerState.members.push({
      id: memberRecordId,
      level: 1,
      user: { uuid: inviteId, email: "product@company.test" },
    });
    const observed8 = await f.service.capture();
    expect(observed8.plan.blockers).toContain(
      "posthog_managed_provider_identity_changed",
    );
  });
  it("cancels an expired owned invitation and permits a new bounded invite next cycle", async () => {
    const f = await fixture();
    await f.service.applyReviewed(await f.reviewed(), f.parent);
    const invite = f.providerState.invites[0];
    if (!invite) throw new Error("fixture_invite_missing");
    invite["is_expired"] = true;
    const cancel = await f.reviewed();
    expect(cancel.action.type).toBe("cancel-invite");
    await f.service.applyReviewed(cancel, f.parent);
    const observed9 = await f.reviewed();
    expect(observed9.action.type).toBe("invite");
  });
  it("excludes inactive people and contractors from grants", async () => {
    const f = await fixture();
    const user = f.users[1];
    if (user) user.suspended = true;
    const observed10 = await f.service.capture();
    expect(observed10.desired.map((p) => p.email)).toEqual([
      "owner@company.test",
    ]);
    if (user) user.suspended = false;
    f.authority.excludedGoogleUserIds.push("222222");
    const observed11 = await f.service.capture();
    expect(observed11.plan.actions).toEqual([]);
  });
  it("retains retired adoption tombstones instead of re-adopting a later manual grant", async () => {
    const provider = snapshot();
    provider.members.push({
      id: memberRecordId,
      level: 1,
      user: { uuid: target, email: "product@company.test" },
    });
    const result = await planPosthogMemberships({
      policy: { ...policy, adoptedGrants: [grant()] },
      desired: [],
      googleUsers: people,
      grants: [grant({ state: "retired" })],
      provider,
    });
    expect(result.actions).toEqual([]);
  });
});

function apiClient(fetchImpl: typeof fetch) {
  return new PosthogMembershipClient({
    origin: policy.origin,
    organizationId: org,
    actorUuid: actor,
    token: "test-token",
    fetchImpl,
  });
}
function urlOf(input: RequestInfo | URL) {
  return input instanceof Request ? input.url : input.toString();
}
function response(value: unknown) {
  return Response.json(value);
}
function readFetch(next: string | null = null) {
  return vi.fn<typeof fetch>((input) => {
    const url = new URL(urlOf(input));
    if (url.pathname === "/api/users/@me/")
      return Promise.resolve(response({ uuid: actor }));
    if (url.pathname.endsWith("/members/"))
      return Promise.resolve(response({ results: snapshot().members, next }));
    if (url.pathname.endsWith("/invites/"))
      return Promise.resolve(response({ results: [], next: null }));
    return Promise.resolve(response({ id: org }));
  });
}
describe("PostHog credential and endpoint boundaries", () => {
  it("reads the pinned organization and actor without following redirects", async () => {
    const transport = readFetch();
    const observed12 = await apiClient(transport).read();
    expect(observed12.organizationId).toBe(org);
    for (const [, init] of transport.mock.calls)
      expect(init).toMatchObject({
        redirect: "manual",
        headers: { authorization: "Bearer test-token" },
      });
  });
  it.each([
    "https://attacker.test/collect",
    `https://us.posthog.com/api/organizations/${actor}/members/`,
  ])(
    "rejects pagination outside the pinned membership path: %s",
    async (next) => {
      const transport = readFetch(next);
      await expect(apiClient(transport).read()).rejects.toThrow(
        "posthog_pagination_authority_mismatch",
      );
      expect(
        transport.mock.calls.some(([input]) => urlOf(input) === next),
      ).toBe(false);
    },
  );
  it("bounds repeated pagination and rejects HTTP redirects without leaking response bodies", async () => {
    await expect(
      apiClient(
        readFetch(
          `https://us.posthog.com/api/organizations/${org}/members/?limit=100`,
        ),
      ).read(),
    ).rejects.toThrow("posthog_pagination_bound");
    const transport = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        new Response("private-body", {
          status: 302,
          headers: { location: "https://attacker.test" },
        }),
      ),
    );
    await expect(apiClient(transport).read()).rejects.toThrow(
      "posthog_membership_http_302",
    );
    expect(transport).toHaveBeenCalledOnce();
  });
  it("invites only Members and uses the user's immutable UUID for deletion", async () => {
    const transport = vi.fn<typeof fetch>((_input, init) =>
      Promise.resolve(
        init?.method === "POST"
          ? response({
              id: inviteId,
              "target_email": "product@company.test",
              level: 1,
              "is_expired": false,
              "created_by": { uuid: actor },
            })
          : new Response(null, { status: 204 }),
      ),
    );
    const client = apiClient(transport);
    await client.invite("PRODUCT@company.test");
    await client.removeMember(target);
    expect(transport.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({
        "target_email": "product@company.test",
        level: 1,
        "send_email": true,
      }),
    );
    expect(urlOf(transport.mock.calls[1]?.[0] ?? "")).toBe(
      `https://us.posthog.com/api/organizations/${org}/members/${target}/`,
    );
  });
  it("rejects an actor mismatch and elevated invitation acknowledgement", async () => {
    const transport = vi.fn<typeof fetch>(() =>
      Promise.resolve(response({ uuid: target })),
    );
    await expect(apiClient(transport).read()).rejects.toThrow(
      "posthog_actor_mismatch",
    );
    const invite = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        response({
          id: inviteId,
          "target_email": "product@company.test",
          level: 8,
          "is_expired": false,
          "created_by": { uuid: actor },
        }),
      ),
    );
    await expect(
      apiClient(invite).invite("product@company.test"),
    ).rejects.toThrow("posthog_invitation_acknowledgement_mismatch");
  });
});
