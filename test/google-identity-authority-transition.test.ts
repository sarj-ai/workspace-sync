import { describe, expect, it } from "vitest";

import { deriveGoogleIdentityAuthorityTransition } from "../src/identity-sync/derive-google-identity-authority-transition.ts";
import {
  GitHubIdentitySeedArtifactSchema,
  planGitHubIdentitySeed,
} from "../src/identity-sync/github-identity-seed-planner.ts";
import { GoogleGitHubIdentitySeedPlanSchema } from "../src/identity-sync/google-github-identity-seed-service.ts";
import { sha256Hex } from "../src/operations/canonical.ts";
import { JsonValueSchema } from "../src/operations/schemas.ts";
import { googleAuthorityFingerprintRecord } from "../src/org-sync/google-directory-authority.ts";
import {
  GitHubLoginSchema,
  GoogleGitHubIdentityPlanSchema,
} from "../src/org-sync/google-identity-schema.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";

const GITHUB_SOURCE = "a".repeat(64);
const DESIRED = { githubLogin: "engineer", githubUserId: "1001" };
const TARGET = {
  id: "101",
  primaryEmail: "engineer@company.test",
  etag: "original-etag",
  isAdmin: false,
  isDelegatedAdmin: false,
  suspended: false,
  archived: false,
  aliases: ["alias@company.test"],
  nonEditableAliases: ["historical@company.test"],
  name: { fullName: "Engineer Person" },
  customSchemas: { SocialBot: { linkedinDigestOptOut: true } },
} satisfies GoogleDirectoryUser;
const OTHER = {
  id: "202",
  primaryEmail: "other@company.test",
  etag: "other-etag",
  isAdmin: false,
  isDelegatedAdmin: false,
  customSchemas: {
    SarjIdentity: { githubLogin: "other", githubUserId: "2002" },
  },
} satisfies GoogleDirectoryUser;
const DELETED = {
  id: "303",
  primaryEmail: "deleted@company.test",
  deletionTime: "2026-09-01T00:00:00Z",
} satisfies GoogleDirectoryUser;

function fingerprint(users: readonly GoogleDirectoryUser[]) {
  return sha256Hex(
    JsonValueSchema.parse(
      users
        .map(googleAuthorityFingerprintRecord)
        .toSorted((left, right) => left.id.localeCompare(right.id)),
    ),
  );
}

async function fixture(target: GoogleDirectoryUser = structuredClone(TARGET)) {
  const users: GoogleDirectoryUser[] = [
    target,
    structuredClone(OTHER),
    structuredClone(DELETED),
  ];
  const expectedBeforeFingerprint = await fingerprint(users);
  const artifact = await planGitHubIdentitySeed({
    githubMembers: [DESIRED, OTHER.customSchemas.SarjIdentity],
    googleUsers: users.slice(0, 2).map((user, index) => ({
      displayName: user.primaryEmail,
      googleUserId: user.id,
      primaryEmail: user.primaryEmail,
      lifecycle: "active",
      githubEvidence: {
        ...(index === 0 ? DESIRED : OTHER.customSchemas.SarjIdentity),
        source: "github-enterprise-saml",
        verifiedAt: "2026-09-01T00:00:00Z",
      },
    })),
    sourceRevision: `${expectedBeforeFingerprint}:${GITHUB_SOURCE}`,
  });
  const plan = GoogleGitHubIdentitySeedPlanSchema.parse({
    kind: "managed",
    artifact,
    githubSourceFingerprint: GITHUB_SOURCE,
    maxChanges: 1,
    maxProviderReads: 6,
    userPlans: [
      {
        kind: "update",
        current: null,
        desired: DESIRED,
        user: {
          id: target.id,
          primaryEmail: target.primaryEmail,
          etag: target.etag,
        },
      },
      {
        kind: "unchanged",
        identity: OTHER.customSchemas.SarjIdentity,
        user: {
          id: OTHER.id,
          primaryEmail: OTHER.primaryEmail,
          etag: OTHER.etag,
        },
      },
    ],
  });
  if (plan.kind !== "managed") throw new Error("expected managed fixture");
  return {
    users,
    reviewedSeedPlan: plan,
    expectedBeforeFingerprint,
    expectedGithubSourceFingerprint: GITHUB_SOURCE,
  };
}

describe("Pure reviewed Google authority transition", () => {
  it("derives only the exact managed-field substitution, preserves frozen input, and returns no population payload", async () => {
    const input = await fixture();
    const before = structuredClone(input);
    deepFreeze(input);
    const expectedUsers = before.users.map((user) =>
      user.id !== TARGET.id
        ? user
        : {
            ...user,
            customSchemas: { ...user.customSchemas, SarjIdentity: DESIRED },
          },
    );
    await expect(
      deriveGoogleIdentityAuthorityTransition(input),
    ).resolves.toEqual({
      googleUserId: TARGET.id,
      beforeFingerprint: before.expectedBeforeFingerprint,
      afterFingerprint: await fingerprint(expectedUsers),
    });
    expect(input).toEqual(before);
    const reversed = { ...before, users: before.users.toReversed() };
    await expect(
      deriveGoogleIdentityAuthorityTransition(reversed),
    ).resolves.toEqual(await deriveGoogleIdentityAuthorityTransition(input));
  });

  it.each([
    { expectedBeforeFingerprint: "b".repeat(64) },
    { expectedGithubSourceFingerprint: "b".repeat(64) },
  ])("rejects stale independently expected source pins %j", async (patch) => {
    await expect(
      deriveGoogleIdentityAuthorityTransition({
        ...(await fixture()),
        ...patch,
      }),
    ).rejects.toThrow();
  });

  it.each([
    { isAdmin: true },
    { isDelegatedAdmin: true },
    { isAdmin: undefined },
    { isDelegatedAdmin: undefined },
    { suspended: true },
    { archived: true },
    { deletionTime: "2026-09-01T00:00:00Z" },
    { aliases: ["root-admin@company.test"] },
    { nonEditableAliases: ["root-admin@company.test"] },
    { id: "999999999999999999901" },
    { id: "999999999999999999903" },
  ] satisfies Partial<GoogleDirectoryUser>[])(
    "rejects an ineligible exact target %j",
    async (patch) => {
      await expect(
        deriveGoogleIdentityAuthorityTransition(
          await fixture({ ...TARGET, ...patch }),
        ),
      ).rejects.toThrow();
    },
  );

  it.each([
    "missing",
    "duplicate",
    "alias-collision",
    "immutable-replacement",
    "unrelated-drift",
  ] as const)(
    "rejects changed or ambiguous original authority: %s",
    async (kind) => {
      const input = await fixture();
      if (kind === "missing") input.users.shift();
      if (kind === "duplicate") input.users.push(structuredClone(TARGET));
      if (kind === "alias-collision")
        input.users[1] = { ...OTHER, aliases: TARGET.aliases };
      if (kind === "immutable-replacement")
        input.users[0] = { ...TARGET, id: "909" };
      if (kind === "unrelated-drift")
        input.users[1] = { ...OTHER, isAdmin: true };
      await expect(
        deriveGoogleIdentityAuthorityTransition(input),
      ).rejects.toThrow();
    },
  );

  it.each([
    "etag",
    "email",
    "current",
    "desired",
    "no-update",
    "two-updates",
    "duplicate-plan",
    "missing-plan",
    "read-cap",
  ] as const)("rejects inconsistent reviewed user plans: %s", async (kind) => {
    const input = await fixture();
    const plan = input.reviewedSeedPlan;
    const update = plan.userPlans[0];
    if (update?.kind !== "update") throw new Error("expected update fixture");
    switch (kind) {
      case "etag":
        update.user.etag = "changed";
        break;
      case "email":
        update.user.primaryEmail = "other@company.test";
        break;
      case "current":
        update.current = { githubLogin: GitHubLoginSchema.parse("incorrect") };
        break;
      case "desired":
        update.desired.githubLogin = GitHubLoginSchema.parse("incorrect");
        break;
      case "no-update":
        plan.userPlans[0] = {
          kind: "unchanged",
          identity: update.desired,
          user: update.user,
        };
        break;
      case "two-updates":
        plan.userPlans[1] = GoogleGitHubIdentityPlanSchema.parse({
          kind: "update",
          desired: OTHER.customSchemas.SarjIdentity,
          current: null,
          user: {
            id: OTHER.id,
            etag: OTHER.etag,
            primaryEmail: OTHER.primaryEmail,
          },
        });
        break;
      case "duplicate-plan":
        plan.userPlans.push(structuredClone(update));
        break;
      case "missing-plan":
        plan.userPlans.pop();
        break;
      case "read-cap":
        plan.maxProviderReads = 1;
        break;
    }
    await expect(
      deriveGoogleIdentityAuthorityTransition(input),
    ).rejects.toThrow();
  });

  it.each([
    "hash",
    "source",
    "subject",
    "evidence",
    "missing-subject",
  ] as const)(
    "rejects inconsistent artifact evidence even with a recomputed content hash: %s",
    async (kind) => {
      const input = await fixture();
      const { contentHash: _hash, ...body } = input.reviewedSeedPlan.artifact;
      const first = body.entries[0];
      if (first?.kind !== "exact-match")
        throw new Error("expected exact artifact entry");
      const entry =
        kind === "subject"
          ? {
              ...first,
              subject: {
                ...first.subject,
                primaryEmail: "replacement@company.test",
              },
            }
          : kind === "evidence"
            ? {
                ...first,
                evidence: { ...first.evidence, githubUserId: "9999" },
              }
            : first;
      const artifactBody = {
        ...body,
        sourceRevision:
          kind === "source"
            ? `${"b".repeat(64)}:${GITHUB_SOURCE}`
            : body.sourceRevision,
        entries:
          kind === "missing-subject"
            ? [entry]
            : [entry, ...body.entries.slice(1)],
        summary:
          kind === "missing-subject"
            ? { ...body.summary, exactMatches: 1 }
            : body.summary,
      };
      input.reviewedSeedPlan.artifact = GitHubIdentitySeedArtifactSchema.parse({
        ...artifactBody,
        contentHash: await sha256Hex(JsonValueSchema.parse(artifactBody)),
      });
      if (kind === "hash")
        input.reviewedSeedPlan.artifact =
          GitHubIdentitySeedArtifactSchema.parse({
            ...input.reviewedSeedPlan.artifact,
            contentHash: "b".repeat(64),
          });
      await expect(
        deriveGoogleIdentityAuthorityTransition(input),
      ).rejects.toThrow();
    },
  );

  it("preserves unknown privilege evidence for unselected records instead of normalizing it to false", async () => {
    const input = await fixture();
    const result = await deriveGoogleIdentityAuthorityTransition(input);
    const expected = input.users.map((user) =>
      user.id === TARGET.id
        ? {
            ...user,
            customSchemas: { ...user.customSchemas, SarjIdentity: DESIRED },
          }
        : user,
    );
    const unsafeNormalization = expected.map((user) => ({
      ...user,
      isAdmin: user.isAdmin ?? false,
      isDelegatedAdmin: user.isDelegatedAdmin ?? false,
    }));
    expect(result.afterFingerprint).toBe(await fingerprint(expected));
    expect(result.afterFingerprint).not.toBe(
      await fingerprint(unsafeNormalization),
    );
  });

  it.each(["duplicate-id", "alias-collision"] as const)(
    "rejects invalid source structure even when its fingerprint and artifact revision match: %s",
    async (kind) => {
      const input = await fixture();
      if (kind === "duplicate-id") input.users.push(structuredClone(TARGET));
      else input.users[1] = { ...OTHER, nonEditableAliases: TARGET.aliases };
      input.expectedBeforeFingerprint = await fingerprint(input.users);
      const { contentHash: _hash, ...original } =
        input.reviewedSeedPlan.artifact;
      const body = {
        ...original,
        sourceRevision: `${input.expectedBeforeFingerprint}:${GITHUB_SOURCE}`,
      };
      input.reviewedSeedPlan.artifact = GitHubIdentitySeedArtifactSchema.parse({
        ...body,
        contentHash: await sha256Hex(JsonValueSchema.parse(body)),
      });
      await expect(
        deriveGoogleIdentityAuthorityTransition(input),
      ).rejects.toThrow();
    },
  );
});

function deepFreeze(value: unknown): void {
  if (!(value instanceof Object)) return;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
}
