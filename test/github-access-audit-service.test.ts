import { describe, expect, it } from "vitest";

import type { GitHubAccessSnapshot } from "../src/github-access-audit/git-hub-access-audit-client.ts";
import type { GoogleAuthoritySnapshot } from "../src/github-access-audit/google-contracts.ts";
import { buildGithubAccessAuditReport } from "../src/github-access-audit/service.ts";

const POLICY = {
  activeOutsideRootRemovals: "blocked",
  excludedGroupEmails: ["team-product-elevated-permissions@company.test"],
  membershipGraceMs: 24 * 60 * 60 * 1000,
  organization: "example",
  policyVersion: "test-v1",
  reportsIngestionMarginMs: 30 * 60 * 1000,
  rootGroupEmail: "team-eng@company.test",
  teamMappings: {
    "team-service-elevated-permissions@company.test":
      "voice-elevated-permissions",
    "team-service-eng@company.test": "eng-platform",
  },
  teamPins: { "eng-platform": 10, "voice-elevated-permissions": 11 },
  unmanagedGithubTeams: ["solutions"],
} as const;
const REVIEWED_OUTSIDE_ROOT_POLICY = {
  ...POLICY,
  activeOutsideRootRemovals: "reviewed",
} as const;

function google(): GoogleAuthoritySnapshot {
  return {
    capturedAt: "2026-01-01T00:00:00.000Z",
    complete: true,
    groups: [
      { email: "team-eng@company.test", id: "g-root" },
      { email: "team-contractors@company.test", id: "contractor-group-test" },
      {
        email: "team-product-elevated-permissions@company.test",
        id: "g-no-target",
      },
      { email: "team-service-eng@company.test", id: "g-voice" },
      {
        email: "team-service-elevated-permissions@company.test",
        id: "g-elevated",
      },
    ],
    issues: [],
    memberships: [
      {
        groupId: "g-root",
        memberEmail: "team-service-eng@company.test",
        memberId: "g-voice",
        memberType: "GROUP",
      },
      {
        groupId: "g-voice",
        memberEmail: "ada@company.test",
        memberId: "u-ada",
        memberType: "USER",
      },
      {
        groupId: "g-elevated",
        memberEmail: "grace@company.test",
        memberId: "u-grace",
        memberType: "USER",
      },
    ],
    reachableGroupIds: ["g-root", "g-voice", "g-elevated", "g-no-target"],
    reports: { events: [], status: "available" },
    unmappedDescendantGroups: [],
    users: [
      {
        aliases: ["ada.alias@company.test"],
        archived: false,
        deleted: false,
        id: "u-ada",
        primaryEmail: "ada@company.test",
        suspended: false,
      },
      {
        aliases: [],
        archived: false,
        deleted: false,
        id: "u-grace",
        primaryEmail: "grace@company.test",
        suspended: false,
      },
    ],
  };
}

function github(): GitHubAccessSnapshot {
  return {
    capturedAt: "2026-01-01T00:00:00.000Z",
    errors: [
      {
        capability: "scim_identities",
        code: "http_404",
        message: "github_http_404",
      },
    ],
    invitations: [],
    members: [{ id: 1, login: "ada-gh", role: "member", type: "User" }],
    organization: {
      "default_repository_permission": "read",
      id: 100_000_001,
      login: "example",
      "members_can_create_repositories": false,
    },
    outsideCollaborators: [{ id: 9, login: "vendor", type: "User" }],
    repositories: [
      {
        archived: false,
        directCollaborators: [
          {
            id: 9,
            login: "vendor",
            permissions: { admin: false, pull: true, push: false },
            type: "User",
          },
        ],
        "full_name": "example/core",
        id: 20,
        name: "core",
        teamGrants: [{ id: 10, permission: "push", slug: "eng-platform" }],
        visibility: "internal",
      },
    ],
    samlExternalIdentities: [
      { guid: "x", login: "ada-gh", nameId: "ada.alias@company.test" },
    ],
    scimIdentities: [],
    teams: [
      {
        directMembers: [],
        id: 10,
        maintainers: [],
        name: "Voice",
        parent: null,
        privacy: "closed",
        slug: "eng-platform",
      },
      {
        directMembers: [],
        id: 11,
        maintainers: [],
        name: "Service elevated",
        parent: { id: 10, slug: "eng-platform" },
        privacy: "closed",
        slug: "voice-elevated-permissions",
      },
    ],
  };
}

describe("GitHub access audit report", () => {
  it.each([
    "exact",
    "google",
    "github",
    "permission",
    "extra-grant",
    "inactive",
    "incomplete",
    "owner",
  ] as const)(
    "recognizes retained direct grants only while the complete review matches (%s)",
    async (boundary) => {
      const source = google();
      const target = github();
      const ada = source.users[0];
      const repository = target.repositories[0];
      if (ada === undefined || repository === undefined)
        throw new Error("fixture");
      if (boundary === "inactive") ada.suspended = true;
      if (boundary === "incomplete") source.complete = false;
      if (boundary === "owner")
        target.members = [
          { id: 1, login: "ada-gh", role: "admin", type: "User" },
        ];
      repository.directCollaborators = [
        {
          id: 1,
          login: "ada-gh",
          type: "User",
          permissions: {
            admin: false,
            pull: true,
            push: boundary === "permission",
          },
        },
      ];
      if (boundary === "extra-grant")
        target.repositories.push({
          ...repository,
          id: 21,
          "full_name": "example/extra",
          name: "extra",
        });
      const report = await buildGithubAccessAuditReport(source, target, {
        ...POLICY,
        reviewedDirectGrantRetentions: [
          {
            allowedTeamSlugs: ["eng-platform"],
            githubLogin: "ada-gh",
            githubUserId: boundary === "github" ? "999" : "1",
            googleUserId: boundary === "google" ? "other" : "u-ada",
            primaryEmail: "ada@company.test",
            reviewedAt: "2026-11-04",
            grants: [
              {
                repositoryId: 20,
                repositoryName: "example/core",
                permission: "pull",
              },
            ],
          },
        ],
      });
      const exceptions = report.proposedChanges.filter(
        (change) =>
          change.id.startsWith("policy_exception:direct_repository_grant:") &&
          change.subject.login === "ada-gh",
      );
      expect(exceptions.length === 0).toBe(boundary === "exact");
      expect(
        report.warnings.includes(
          "Reviewed existing GitHub direct repository grants retained: @ada-gh",
        ),
      ).toBe(boundary === "exact");
      expect(report.inventory.repositories[0]?.directCollaborators).toEqual(
        repository.directCollaborators,
      );
    },
  );

  it.each([
    "exact",
    "google",
    "github",
    "team",
    "inactive",
    "maintainer",
  ] as const)(
    "honors only the exact active reviewed membership (%s)",
    async (boundary) => {
      const source = google();
      source.memberships = source.memberships.filter(
        ({ memberId }) => memberId !== "u-ada",
      );
      source.memberships.push({
        groupId: "g-root",
        memberId: "u-ada",
        memberEmail: "ada@company.test",
        memberType: "USER",
      });
      const target = github();
      const team = target.teams[0];
      const ada = source.users.find(({ id }) => id === "u-ada");
      if (team === undefined || ada === undefined) throw new Error("fixture");
      team.directMembers.push({ id: 1, login: "ada-gh", type: "User" });
      if (boundary === "inactive") ada.suspended = true;
      if (boundary === "maintainer")
        team.maintainers.push({ id: 1, login: "ada-gh", type: "User" });
      const report = await buildGithubAccessAuditReport(source, target, {
        ...POLICY,
        reviewedTeamMemberships: [
          {
            googleUserId: boundary === "google" ? "other" : "u-ada",
            githubUserId: boundary === "github" ? "999" : "1",
            githubLogin: "ada-gh",
            teamId: boundary === "team" ? 999 : 10,
            teamSlug: "eng-platform",
            reviewedAt: "2026-11-04",
          },
        ],
      });
      const removal = report.proposedChanges.some(
        (change) =>
          change.kind === "team_remove" && change.subject.login === "ada-gh",
      );
      expect(removal).toBe(boundary !== "exact");
      expect(
        report.warnings.includes(
          "Reviewed existing GitHub team membership retained: @ada-gh in eng-platform",
        ),
      ).toBe(boundary === "exact");
    },
  );

  it("is deterministic across timestamps and reports readiness blockers", async () => {
    const first = await buildGithubAccessAuditReport(
      google(),
      github(),
      POLICY,
      new Date("2026-01-01"),
    );
    const second = await buildGithubAccessAuditReport(
      google(),
      github(),
      POLICY,
      new Date("2026-01-02"),
    );
    expect(first.contentHash).toBe(second.contentHash);
    expect(first.complete).toBe(true);
    expect(first.samlScimReadiness.blockers).toEqual(
      expect.arrayContaining([
        expect.stringContaining("SCIM identity data is unavailable"),
        expect.stringContaining("internal repositories"),
      ]),
    );
    expect(first.inventory.outsideCollaborators).toEqual(["vendor"]);
    expect(first.repositoryAccess).toContainEqual(
      expect.objectContaining({
        after: "push",
        login: "ada-gh",
        repository: "example/core",
      }),
    );
  });

  it("hashes logically identical API orderings identically", async () => {
    const ordered = github();
    const reversed = github();
    reversed.teams.reverse();
    reversed.repositories.reverse();
    const first = await buildGithubAccessAuditReport(
      google(),
      ordered,
      POLICY,
      new Date("2026-01-01"),
    );
    const second = await buildGithubAccessAuditReport(
      google(),
      reversed,
      POLICY,
      new Date("2026-01-02"),
    );
    expect(first.contentHash).toBe(second.contentHash);
  });

  it("never marks audit findings actionable and blocks incomplete removals", async () => {
    const source = google();
    source.complete = false;
    source.memberships = [];
    source.issues.push({ code: "page_limit", message: "partial traversal" });
    const report = await buildGithubAccessAuditReport(source, github(), POLICY);
    expect(report.complete).toBe(false);
    expect(
      report.proposedChanges.every((change) => !change.safelyActionable),
    ).toBe(true);
  });

  it("suppresses identity-derived access deltas when the SAML capability is unavailable", async () => {
    const snapshot = github();
    snapshot.errors.push({
      capability: "saml_external_identities",
      code: "http_403",
      message: "github_http_403",
    });
    snapshot.samlExternalIdentities = [];

    const report = await buildGithubAccessAuditReport(
      google(),
      snapshot,
      POLICY,
    );

    expect(report.complete).toBe(false);
    expect(report.errors).toContainEqual(
      expect.stringContaining("saml_external_identities"),
    );
    expect(report.samlScimReadiness.samlIdentityDataAvailable).toBe(false);
    expect(report.proposedChanges).not.toContainEqual(
      expect.objectContaining({
        kind: expect.stringMatching(/^(?:org|team)_(?:add|remove)$/u),
      }),
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({
        kind: "policy_exception",
        subject: expect.objectContaining({ login: "vendor" }),
      }),
    );
  });

  it("suppresses identity-derived access deltas when the SAML inventory is unexpectedly empty", async () => {
    const snapshot = github();
    snapshot.errors = [];
    snapshot.samlExternalIdentities = [];
    snapshot.scimIdentities = [scim("ada@company.test")];

    const report = await buildGithubAccessAuditReport(
      google(),
      snapshot,
      POLICY,
    );

    expect(report.complete).toBe(false);
    expect(report.samlScimReadiness.blockers).toContainEqual(
      expect.stringContaining("SAML/SCIM identity inventory is empty"),
    );
    expect(report.proposedChanges).not.toContainEqual(
      expect.objectContaining({
        kind: expect.stringMatching(/^(?:org|team)_(?:add|remove)$/u),
      }),
    );
  });

  it("preserves Excluded person GitHub access for review and proposes no employee grants", async () => {
    const googleSnapshot = google();
    googleSnapshot.users.push({
      aliases: [],
      archived: false,
      deleted: false,
      id: "u-excludedperson",
      primaryEmail: "excluded-four@company.test",
      suspended: false,
    });
    googleSnapshot.memberships.push({
      groupId: "g-voice",
      memberEmail: "excluded-four@company.test",
      memberId: "u-excludedperson",
      memberType: "USER",
    });
    const githubSnapshot = github();
    githubSnapshot.members.push({
      id: 3,
      login: "excludedperson-gh",
      role: "member",
      type: "User",
    });
    githubSnapshot.teams[0]?.directMembers.push({
      id: 3,
      login: "excludedperson-gh",
      type: "User",
    });
    githubSnapshot.samlExternalIdentities.push({
      guid: "excludedperson-guid",
      login: "excludedperson-gh",
      nameId: "excluded-four@company.test",
    });

    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      githubSnapshot,
      POLICY,
    );
    const changes = report.proposedChanges.filter(
      (change) => change.subject.email === "excluded-four@company.test",
    );
    expect(changes).toEqual([
      expect.objectContaining({
        kind: "policy_exception",
        safelyActionable: false,
      }),
    ]);
  });

  it.each(["SUSPENDED", "ARCHIVED", "UNKNOWN"] as const)(
    "classifies contractor authority completeness for %s membership",
    async (status) => {
      const source = google();
      source.memberships.push({
        groupId: "contractor-group-test",
        memberEmail: "ada@company.test",
        memberId: "u-ada",
        memberType: "USER",
        role: "MEMBER",
        status,
      });
      const report = await buildGithubAccessAuditReport(
        source,
        github(),
        POLICY,
      );
      expect(
        report.errors.some((error) =>
          error.startsWith("Google contractor authority:"),
        ),
      ).toBe(status === "UNKNOWN");
      expect(
        report.proposedChanges
          .filter((change) => change.subject.email === "ada@company.test")
          .every((change) =>
            status === "UNKNOWN"
              ? !change.safelyActionable
              : change.kind !== "org_add" && change.kind !== "team_add",
          ),
      ).toBe(true);
    },
  );

  it("uses the live contractor group for identities outside the bootstrap denylist", async () => {
    const googleSnapshot = google();
    googleSnapshot.users.push({
      aliases: [],
      archived: false,
      deleted: false,
      id: "u-dynamic-contractor",
      primaryEmail: "dynamic-contractor@company.test",
      suspended: false,
    });
    googleSnapshot.memberships.push(
      {
        groupId: "g-voice",
        memberEmail: "dynamic-contractor@company.test",
        memberId: "u-dynamic-contractor",
        memberType: "USER",
      },
      {
        groupId: "contractor-group-test",
        memberEmail: "dynamic-contractor@company.test",
        memberId: "u-dynamic-contractor",
        memberType: "USER",
        role: "MEMBER",
        status: "ACTIVE",
      },
    );
    const githubSnapshot = github();
    githubSnapshot.members.push({
      id: 4,
      login: "dynamic-contractor-gh",
      role: "member",
      type: "User",
    });
    githubSnapshot.samlExternalIdentities.push({
      guid: "dynamic-contractor-guid",
      login: "dynamic-contractor-gh",
      nameId: "dynamic-contractor@company.test",
    });

    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      githubSnapshot,
      POLICY,
    );
    expect(
      report.proposedChanges.filter(
        (change) => change.subject.email === "dynamic-contractor@company.test",
      ),
    ).toEqual([
      expect.objectContaining({
        kind: "policy_exception",
        safelyActionable: false,
      }),
    ]);
  });

  it("flags elevated membership outside the parent engineering group", async () => {
    const googleSnapshot = google();
    googleSnapshot.memberships.push({
      groupId: "g-root",
      memberEmail: "grace@company.test",
      memberId: "u-grace",
      memberType: "USER",
    });
    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      github(),
      POLICY,
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({
        kind: "policy_exception",
        reason: expect.stringContaining("subset of eng-platform"),
        safelyActionable: false,
      }),
    );
  });

  it("classifies a recent authoritative removal as pending grace", async () => {
    const googleSnapshot = google();
    googleSnapshot.reports = {
      events: [
        {
          groupEmail: "team-eng@company.test",
          name: "REMOVE_GROUP_MEMBER",
          parameters: { "USER_EMAIL": ["grace@company.test"] },
          subjectEmail: "grace@company.test",
          time: "2026-01-01T10:00:00.000Z",
        },
      ],
      status: "available",
    };
    const githubSnapshot = github();
    githubSnapshot.members.push({
      id: 2,
      login: "grace-gh",
      role: "member",
      type: "User",
    });
    githubSnapshot.samlExternalIdentities.push({
      guid: "grace-guid",
      login: "grace-gh",
      nameId: "grace@company.test",
    });
    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      githubSnapshot,
      REVIEWED_OUTSIDE_ROOT_POLICY,
      new Date("2026-01-01T12:00:00.000Z"),
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({ grace: "pending_grace", kind: "org_remove" }),
    );
  });

  it("blocks removal of an active member outside the provisional organizational root", async () => {
    const report = await buildGithubAccessAuditReport(
      google(),
      githubWithGraceMember(),
      POLICY,
    );
    const changes = report.proposedChanges.filter(
      ({ subject }) => subject.email === "grace@company.test",
    );

    expect(changes).not.toContainEqual(
      expect.objectContaining({ kind: "org_remove" }),
    );
    expect(changes).toContainEqual(
      expect.objectContaining({
        kind: "policy_exception",
        reason: expect.stringContaining("access-github-org"),
        safelyActionable: false,
      }),
    );
  });

  it.each([
    {
      events: [
        {
          groupEmail: "team-eng@company.test",
          name: "REMOVE_GROUP_MEMBER",
          parameters: { "USER_EMAIL": ["grace@company.test"] },
          subjectEmail: "grace@company.test",
          time: "2025-12-30T00:00:00.000Z",
        },
      ],
      expected: "grace_elapsed",
    },
    {
      events: [
        {
          groupEmail: "team-eng@company.test",
          name: "REMOVE_GROUP_MEMBER",
          parameters: { "USER_EMAIL": ["grace@company.test"] },
          subjectEmail: "grace@company.test",
          time: "2025-12-30T00:00:00.000Z",
        },
        {
          groupEmail: "team-eng@company.test",
          name: "ADD_GROUP_MEMBER",
          parameters: { "USER_EMAIL": ["grace@company.test"] },
          subjectEmail: "grace@company.test",
          time: "2025-12-31T00:00:00.000Z",
        },
      ],
      expected: "conflicted",
    },
  ])(
    "classifies report-backed removals as $expected",
    async ({ events, expected }) => {
      const googleSnapshot = google();
      googleSnapshot.reports = { events, status: "available" };
      const githubSnapshot = githubWithGraceMember();
      const report = await buildGithubAccessAuditReport(
        googleSnapshot,
        githubSnapshot,
        REVIEWED_OUTSIDE_ROOT_POLICY,
        new Date("2026-01-01T12:00:00.000Z"),
      );
      expect(report.proposedChanges).toContainEqual(
        expect.objectContaining({ grace: expected, kind: "org_remove" }),
      );
    },
  );

  it("classifies suspended accounts for immediate removal", async () => {
    const googleSnapshot = google();
    const grace = googleSnapshot.users.find(
      (user) => user.primaryEmail === "grace@company.test",
    );
    if (!grace) throw new Error("test fixture missing grace user");
    grace.suspended = true;
    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      githubWithGraceMember(),
      POLICY,
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({
        grace: "immediate_authoritative",
        kind: "org_remove",
      }),
    );
  });

  it("rejects ambiguous SAML correlations instead of choosing a login", async () => {
    const snapshot = github();
    snapshot.samlExternalIdentities.push({
      guid: "duplicate",
      login: "ada-duplicate",
      nameId: "ada@company.test",
    });
    snapshot.members.push({
      id: 2,
      login: "ada-duplicate",
      role: "member",
      type: "User",
    });
    const report = await buildGithubAccessAuditReport(
      google(),
      snapshot,
      POLICY,
    );
    expect(report.identityMismatches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          email: "ada@company.test",
          reason: expect.stringContaining("multiple GitHub logins"),
        }),
      ]),
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({
        blockers: expect.arrayContaining([
          "No unambiguous GitHub identity correlation",
        ]),
        kind: "org_add",
      }),
    );
  });

  it("includes repository permission inherited through a child team", async () => {
    const snapshot = github();
    snapshot.members.push({
      id: 2,
      login: "grace-gh",
      role: "member",
      type: "User",
    });
    snapshot.samlExternalIdentities.push({
      guid: "grace-guid",
      login: "grace-gh",
      nameId: "grace@company.test",
    });
    snapshot.teams[1]?.directMembers.push({
      id: 2,
      login: "grace-gh",
      type: "User",
    });
    const report = await buildGithubAccessAuditReport(
      google(),
      snapshot,
      POLICY,
    );
    expect(report.repositoryAccess).toContainEqual(
      expect.objectContaining({
        before: "push",
        login: "grace-gh",
        sourcesBefore: expect.arrayContaining(["team:eng-platform"]),
      }),
    );
  });

  it("fails closed when a mapped group is detached from the engineering root", async () => {
    const snapshot = google();
    snapshot.reachableGroupIds = ["g-root"];
    const report = await buildGithubAccessAuditReport(
      snapshot,
      github(),
      POLICY,
    );
    expect(report.complete).toBe(false);
    expect(report.errors).toContainEqual(
      expect.stringContaining("is not a descendant"),
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({
        kind: "policy_exception",
        reason: expect.stringContaining("detached"),
      }),
    );
  });

  it.each([
    { label: "missing", teamPins: { "voice-elevated-permissions": 11 } },
    {
      label: "mismatched",
      teamPins: { "eng-platform": 999, "voice-elevated-permissions": 11 },
    },
  ])(
    "fails closed when a mapped team immutable ID pin is $label",
    async ({ teamPins }) => {
      const report = await buildGithubAccessAuditReport(google(), github(), {
        ...POLICY,
        teamPins,
      });

      expect(report.complete).toBe(false);
      expect(report.errors).toContain(
        "Mapped GitHub team eng-platform immutable ID did not match",
      );
    },
  );

  it("never proposes team access for a suspended child-group member", async () => {
    const googleSnapshot = google();
    const ada = googleSnapshot.users.find(
      (user) => user.primaryEmail === "ada@company.test",
    );
    if (!ada) throw new Error("test fixture missing ada user");
    ada.suspended = true;
    const githubSnapshot = github();
    githubSnapshot.teams[0]?.directMembers.push({
      id: 1,
      login: "ada-gh",
      type: "User",
    });
    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      githubSnapshot,
      POLICY,
    );
    expect(report.proposedChanges).not.toContainEqual(
      expect.objectContaining({
        kind: "team_add",
        subject: expect.objectContaining({ login: "ada-gh" }),
      }),
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({
        kind: "team_remove",
        subject: expect.objectContaining({ login: "ada-gh" }),
      }),
    );
  });

  it("does not age a removal from an unrelated group event", async () => {
    const googleSnapshot = google();
    googleSnapshot.reports = {
      events: [
        {
          groupEmail: "unrelated@company.test",
          name: "REMOVE_GROUP_MEMBER",
          parameters: {},
          subjectEmail: "grace@company.test",
          time: "2025-12-01T00:00:00.000Z",
        },
      ],
      status: "available",
    };
    const report = await buildGithubAccessAuditReport(
      googleSnapshot,
      githubWithGraceMember(),
      REVIEWED_OUTSIDE_ROOT_POLICY,
      new Date("2026-01-01T12:00:00.000Z"),
    );
    expect(report.proposedChanges).toContainEqual(
      expect.objectContaining({ grace: "age_unknown", kind: "org_remove" }),
    );
  });

  it("preserves all GitHub access for explicitly excluded Google-group members", async () => {
    const snapshot = google();
    snapshot.memberships.push({
      groupId: "g-no-target",
      memberEmail: "ada.alias@company.test",
      memberId: "u-ada",
      memberType: "USER",
    });
    const report = await buildGithubAccessAuditReport(
      snapshot,
      github(),
      POLICY,
    );
    expect(report.complete).toBe(true);
    expect(report.inventory.githubExcludedGoogleGroups).toEqual([
      {
        groupEmail: "team-product-elevated-permissions@company.test",
        members: ["ada@company.test"],
      },
    ]);
    expect(
      report.proposedChanges.filter(
        ({ subject }) => subject.email === "ada@company.test",
      ),
    ).toEqual([]);
  });

  it.each([
    { label: "empty SAML", saml: [], scim: [scim("ada@company.test")] },
    {
      label: "extra SCIM",
      saml: [saml("ada@company.test")],
      scim: [
        scim("ada@company.test"),
        scim("extra@company.test", "scim-extra"),
      ],
    },
    {
      label: "extra SAML",
      saml: [saml("ada@company.test"), saml("extra@company.test", "extra-gh")],
      scim: [scim("ada@company.test")],
    },
    {
      label: "duplicate",
      saml: [
        saml("ada@company.test"),
        saml("ada@company.test", "duplicate-gh"),
      ],
      scim: [scim("ada@company.test")],
    },
    {
      label: "inactive SCIM",
      saml: [saml("ada@company.test")],
      scim: [scim("ada@company.test", "scim-1", false)],
    },
    {
      label: "case difference",
      saml: [saml("Ada@company.test")],
      scim: [scim("ada@company.test")],
    },
  ])(
    "fails exact SAML/SCIM readiness for $label",
    async ({ saml: identities, scim: resources }) => {
      const snapshot = github();
      snapshot.errors = [];
      snapshot.samlExternalIdentities = identities;
      snapshot.scimIdentities = resources;
      const report = await buildGithubAccessAuditReport(
        google(),
        snapshot,
        POLICY,
      );
      expect(report.samlScimReadiness.exactNameIdMatchesUserName).toBe(false);
      expect(report.samlScimReadiness.blockers.length).toBeGreaterThan(0);
    },
  );

  it.each([
    {
      identities: [
        { guid: "unlinked", login: null, nameId: "ada@company.test" },
      ],
      label: "an unlinked identity",
      resources: [scim("ada@company.test")],
    },
    {
      identities: [saml("ada@company.test"), saml("grace@company.test")],
      label: "a duplicate linked login",
      resources: [
        scim("ada@company.test"),
        scim("grace@company.test", "scim-2"),
      ],
    },
  ])("blocks readiness for $label", async ({ identities, resources }) => {
    const snapshot = github();
    snapshot.errors = [];
    snapshot.samlExternalIdentities = identities;
    snapshot.scimIdentities = resources;
    const report = await buildGithubAccessAuditReport(
      google(),
      snapshot,
      POLICY,
    );
    expect(report.samlScimReadiness.exactNameIdMatchesUserName).toBe(false);
    expect(report.samlScimReadiness.blockers.length).toBeGreaterThan(0);
  });
});

function githubWithGraceMember(): GitHubAccessSnapshot {
  const snapshot = github();
  snapshot.members.push({
    id: 2,
    login: "grace-gh",
    role: "member",
    type: "User",
  });
  snapshot.samlExternalIdentities.push({
    guid: "grace-guid",
    login: "grace-gh",
    nameId: "grace@company.test",
  });
  return snapshot;
}

function saml(nameId: string, login = "ada-gh") {
  return { guid: `${login}-guid`, login, nameId };
}

function scim(userName: string, id = "scim-1", active = true) {
  return { active, id, userName };
}
