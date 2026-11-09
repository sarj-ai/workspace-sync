import { describe, expect, it } from "vitest";

import type {
  GitHubLogin,
  GitHubUserId,
  PrimaryEmail,
} from "../src/catalog/identity-authority.ts";
import type { GitHubAccessSnapshot } from "../src/github-access-audit/git-hub-access-audit-client.ts";
import { resolveGitHubInvitationActors } from "../src/github/organization-membership-reader.ts";
import { GitHubDeprovisionAuthorityPort } from "../src/identity-provisioning/git-hub-deprovision-authority-port.ts";
import { GitHubOrganizationSnapshotPort } from "../src/identity-provisioning/git-hub-organization-snapshot-port.ts";

const CAPTURED_AT = "2026-08-31T12:00:00.000Z";
const GITHUB_LOGIN = "octocat" as GitHubLogin;
const GITHUB_USER_ID = "583231" as GitHubUserId;
const ORGANIZATION_ID = "100000001";
const ORGANIZATION_LOGIN = "example";
const PRIMARY_EMAIL = "octocat@company.test" as PrimaryEmail;

const TARGET = {
  githubLogin: GITHUB_LOGIN,
  githubUserId: GITHUB_USER_ID,
  primaryEmail: PRIMARY_EMAIL,
} as const;

const CONFIG = {
  managedTeamSlugs: [],
  organizationId: ORGANIZATION_ID,
  organizationLogin: ORGANIZATION_LOGIN,
} as const;

describe("GitHubOrganizationSnapshotPort", () => {
  it("accepts the exact immutable organization ID and login", async () => {
    const port = new GitHubOrganizationSnapshotPort(snapshot(), CONFIG);

    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      complete: true,
      identity: { githubLogin: GITHUB_LOGIN, githubUserId: GITHUB_USER_ID },
      membership: {
        githubLogin: GITHUB_LOGIN,
        githubUserId: GITHUB_USER_ID,
        role: "member",
      },
    });
  });

  it("fails closed when the immutable organization ID does not match", () => {
    expect(
      () =>
        new GitHubOrganizationSnapshotPort(
          snapshot({ organization: { id: 999, login: ORGANIZATION_LOGIN } }),
          CONFIG,
        ),
    ).toThrow("github_organization_snapshot_id_mismatch");
  });

  it("fails closed when the pinned organization login does not match", () => {
    expect(
      () =>
        new GitHubOrganizationSnapshotPort(
          snapshot({
            organization: {
              id: Number(ORGANIZATION_ID),
              login: "lookalike-org",
            },
          }),
          CONFIG,
        ),
    ).toThrow("github_organization_snapshot_login_mismatch");
  });

  it("fails closed when a managed team slug resolves to a different immutable team ID", () => {
    expect(
      () =>
        new GitHubOrganizationSnapshotPort(
          snapshot({
            teams: [
              {
                directMembers: [],
                id: 17,
                maintainers: [],
                name: "Engineering",
                parent: null,
                privacy: "closed",
                slug: "engineering",
              },
            ],
          }),
          {
            ...CONFIG,
            managedTeamPins: { engineering: 999 },
            managedTeamSlugs: ["engineering"],
          },
        ),
    ).toThrow("github_managed_team_pin_mismatch");
  });

  it("fails closed when immutable ID and login resolve to different actors", () => {
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({
        members: [
          {
            id: Number(GITHUB_USER_ID),
            login: "renamed-octocat",
            role: "member",
            type: "User",
          },
          { id: 999_999, login: GITHUB_LOGIN, role: "member", type: "User" },
        ],
      }),
      CONFIG,
    );

    expect(() => port.observeAccount(TARGET)).toThrow(
      "github_organization_snapshot_actor_ambiguous",
    );
  });

  it("attributes an email-only direct-member invitation to the exact target", async () => {
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({
        members: [],
        invitations: [
          {
            email: PRIMARY_EMAIL,
            id: 71,
            invitee: null,
            role: "direct_member",
          },
        ],
      }),
      CONFIG,
    );

    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      pendingInvitations: [
        {
          githubLogin: GITHUB_LOGIN,
          githubUserId: GITHUB_USER_ID,
          invitationId: 71,
          role: "direct_member",
        },
      ],
    });
  });

  it("ignores an unrelated email-only direct-member invitation", async () => {
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({
        members: [],
        invitations: [
          {
            email: "someone-else@company.test",
            id: 72,
            invitee: null,
            role: "direct_member",
          },
        ],
      }),
      CONFIG,
    );

    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      pendingInvitations: [],
    });
  });

  it.each(["admin", "billing_manager", "direct_member"] as const)(
    "quarantines an unattributable unresolved %s invitation on a non-member account",
    async (role) => {
      const port = new GitHubOrganizationSnapshotPort(
        snapshot({
          invitations: [{ email: null, id: 73, invitee: null, role }],
          members: [],
        }),
        CONFIG,
      );

      await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
        membership: null,
        pendingInvitations: [],
        unresolvedInvitations:
          role === "direct_member" ? "opaque-direct" : "identity-or-privilege",
      });
    },
  );

  it("does not let an opaque invitation block a known active member", async () => {
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({
        invitations: [
          { email: null, id: 73, invitee: null, role: "direct_member" },
        ],
      }),
      CONFIG,
    );

    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      membership: { githubUserId: GITHUB_USER_ID },
      pendingInvitations: [],
    });
  });

  it.each(["admin", "billing_manager"] as const)(
    "attributes a target email-only %s invitation so downstream planning cannot omit it",
    async (role) => {
      const port = new GitHubOrganizationSnapshotPort(
        snapshot({
          invitations: [{ email: PRIMARY_EMAIL, id: 74, invitee: null, role }],
        }),
        CONFIG,
      );

      await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
        pendingInvitations: [{ invitationId: 74, role }],
      });
    },
  );

  it("rejects a snapshot whose SAML identity capability is incomplete", () => {
    expect(
      () =>
        new GitHubOrganizationSnapshotPort(
          snapshot({
            errors: [
              {
                capability: "saml_external_identities",
                code: "http_403",
                message: "github_http_403",
              },
            ],
          }),
          CONFIG,
        ),
    ).toThrow("github_organization_snapshot_incomplete");
  });

  it("does not accept a same-login SAML identity linked to a different immutable user ID", async () => {
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({
        samlExternalIdentities: [
          {
            databaseId: 999_999,
            guid: "saml-lookalike",
            login: GITHUB_LOGIN,
            nameId: PRIMARY_EMAIL,
          },
        ],
      }),
      CONFIG,
    );

    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      samlLinked: false,
    });
  });

  it("marks selected-repository visibility as incomplete", async () => {
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({
        organization: {
          id: Number(ORGANIZATION_ID),
          login: ORGANIZATION_LOGIN,
          "owned_private_repos": 2,
          "public_repos": 0,
        },
        repositories: [
          {
            archived: false,
            directCollaborators: [],
            "full_name": "example/visible-one",
            id: 1,
            name: "visible-one",
            teamGrants: [],
            visibility: "private",
          },
        ],
      }),
      CONFIG,
    );
    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      repositoryInventoryComplete: false,
    });
  });
});

function snapshot(
  overrides: Partial<GitHubAccessSnapshot> = {},
): GitHubAccessSnapshot {
  return {
    capturedAt: CAPTURED_AT,
    errors: [],
    invitations: [],
    members: [
      {
        id: Number(GITHUB_USER_ID),
        login: GITHUB_LOGIN,
        role: "member",
        type: "User",
      },
    ],
    organization: {
      id: Number(ORGANIZATION_ID),
      login: ORGANIZATION_LOGIN,
      "owned_private_repos": 0,
      "public_repos": 0,
    },
    outsideCollaborators: [],
    repositories: [],
    samlExternalIdentities: [
      {
        databaseId: Number(GITHUB_USER_ID),
        guid: "saml-1",
        login: GITHUB_LOGIN,
        nameId: "octocat@company.test",
      },
    ],
    scimIdentities: [],
    teams: [],
    ...overrides,
  };
}

describe.each([
  { name: "snapshot", Port: GitHubOrganizationSnapshotPort },
  { name: "deprovision", Port: GitHubDeprovisionAuthorityPort },
])("invitation projection parity $name", ({ Port: portClass }) => {
  function create(captured: GitHubAccessSnapshot) {
    return portClass === GitHubOrganizationSnapshotPort
      ? new GitHubOrganizationSnapshotPort(captured, CONFIG)
      : new GitHubDeprovisionAuthorityPort(
          { ...captured, errors: [] },
          {
            organizationId: ORGANIZATION_ID,
            organizationLogin: ORGANIZATION_LOGIN,
          },
        );
  }
  it.each([
    {
      email: "unrelated@company.test",
      id: 71,
      invitee: null,
      role: "direct_member" as const,
    },
    {
      email: null,
      id: 71,
      login: "unrelated",
      invitee: { id: 999, login: "unrelated", type: "User" as const },
      role: "direct_member" as const,
    },
  ])(
    "does not attribute unrelated invitations to an absent actor",
    async (invitation) => {
      const port = create({
        ...snapshot({ members: [], invitations: [invitation] }),
        errors: [],
      });
      await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
        membership: null,
        pendingInvitations: [],
      });
      await expect(port.observeAccount(TARGET)).resolves.not.toHaveProperty(
        "unresolvedInvitations",
      );
    },
  );
  it("associates exact email-only evidence without requiring an organization actor", async () => {
    const port = create({
      ...snapshot({
        members: [],
        invitations: [
          { id: 71, email: PRIMARY_EMAIL.toUpperCase(), role: "direct_member" },
        ],
      }),
      errors: [],
    });
    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      pendingInvitations: [{ invitationId: 71, githubUserId: GITHUB_USER_ID }],
    });
  });
  it("blocks conflicting email and immutable invitation identity without inventing ownership", async () => {
    const port = create({
      ...snapshot({
        members: [],
        invitations: [
          {
            id: 71,
            email: PRIMARY_EMAIL,
            invitee: { id: 999, login: "unrelated", type: "User" },
            role: "direct_member",
          },
        ],
      }),
      errors: [],
    });
    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      pendingInvitations: [],
      unresolvedInvitations: "identity-or-privilege",
    });
  });
});

describe("documented invitation identity hydration", () => {
  it("resolves top-level login once and preserves the distinct immutable invitation ID", async () => {
    const reads: string[] = [];
    const invitations = await resolveGitHubInvitationActors(
      [
        { id: 71, login: "OctoCat", email: null, role: "direct_member" },
        { id: 72, login: "octocat", email: null, role: "direct_member" },
      ],
      async (login) => {
        reads.push(login);
        return { id: Number(GITHUB_USER_ID), login: "octocat", type: "User" };
      },
    );
    expect(reads).toEqual(["octocat"]);
    expect(
      invitations.map((invite) => [invite.id, invite.invitee?.id]),
    ).toEqual([
      [71, Number(GITHUB_USER_ID)],
      [72, Number(GITHUB_USER_ID)],
    ]);
    const port = new GitHubOrganizationSnapshotPort(
      snapshot({ members: [], invitations }),
      CONFIG,
    );
    await expect(port.observeAccount(TARGET)).resolves.toMatchObject({
      pendingInvitations: [{ invitationId: 71 }, { invitationId: 72 }],
    });
  });
  it.each([
    {
      actor: { id: 999, login: "wrong", type: "User" as const },
      invitee: null,
    },
    {
      actor: { id: 999, login: "octocat", type: "User" as const },
      invitee: { id: 583231, login: "octocat", type: "User" as const },
    },
  ])(
    "rejects profile login or legacy immutable-ID disagreement",
    async ({ actor, invitee }) => {
      await expect(
        resolveGitHubInvitationActors(
          [{ id: 71, login: "octocat", invitee, role: "direct_member" }],
          async () => actor,
        ),
      ).rejects.toThrow("github_invitation_identity_conflict");
    },
  );
  it("does not turn a failed profile read into absence", async () => {
    await expect(
      resolveGitHubInvitationActors(
        [{ id: 71, login: "octocat", role: "direct_member" }],
        async () => {
          throw new Error("profile_unavailable");
        },
      ),
    ).rejects.toThrow("profile_unavailable");
  });
});
