import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import { fingerprintGoogleDirectoryAuthority } from "../org-sync/fingerprint-google-directory-authority.ts";
import {
  GoogleGitHubIdentityPlanSchema,
  GoogleGithubIdentityApplyMaxProviderReads,
  type GoogleGithubIdentityPlan,
} from "../org-sync/google-identity-schema.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../org-sync/model.ts";
import { googleIdentityUpdatesFromSeedPlan } from "./github-identity-seed-planner.ts";
import {
  GoogleGitHubIdentitySeedPlanSchema,
  type GoogleGithubIdentitySeedPlan,
} from "./google-github-identity-seed-service.ts";
import { normalizeIdentityEmail } from "./normalize-identity-email.ts";

type ManagedSeed = Extract<GoogleGithubIdentitySeedPlan, { kind: "managed" }>;
type ExistingUserPlan = Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>;
const INVALID_TRANSITION = "google_identity_authority_transition_invalid";
const CURRENT_IDENTITY = currentIdentitySchema();

function currentIdentitySchema() {
  const update = GoogleGitHubIdentityPlanSchema.options.find(
    ({ shape }) => shape.kind.value === "update",
  );
  if (update === undefined || !("current" in update.shape))
    throw new Error(INVALID_TRANSITION);
  return update.shape.current;
}

/* Derives evidence from the original reviewed snapshot; never authorizes or executes a write. */
export async function deriveGoogleIdentityAuthorityTransition(input: {
  readonly users: readonly GoogleDirectoryUser[];
  readonly reviewedSeedPlan: GoogleGithubIdentitySeedPlan;
  readonly expectedBeforeFingerprint: string;
  readonly expectedGithubSourceFingerprint: string;
}) {
  const plan = GoogleGitHubIdentitySeedPlanSchema.parse(input.reviewedSeedPlan);
  const users = structuredClone(input.users);
  const beforeFingerprint = await fingerprintGoogleDirectoryAuthority(users);
  if (
    plan.kind !== "managed" ||
    beforeFingerprint !== input.expectedBeforeFingerprint ||
    plan.githubSourceFingerprint !== input.expectedGithubSourceFingerprint ||
    plan.artifact.sourceRevision !==
      `${beforeFingerprint}:${input.expectedGithubSourceFingerprint}`
  )
    throw new Error(INVALID_TRANSITION);
  const usersById = indexUsers(users);
  await assertArtifactBinding(plan, usersById);
  const changes = plan.userPlans.filter((item) => item.kind === "update");
  const change = changes[0];
  if (
    changes.length !== 1 ||
    change === undefined ||
    plan.maxProviderReads < GoogleGithubIdentityApplyMaxProviderReads
  )
    throw new Error(INVALID_TRANSITION);
  const target = usersById.get(change.user.id);
  if (target === undefined) throw new Error(INVALID_TRANSITION);
  assertEligibleTarget(target, users);
  for (const userPlan of plan.userPlans) {
    if (userPlan.kind === "blocked") throw new Error(INVALID_TRANSITION);
    assertOriginalUserPlan(userPlan, usersById.get(userPlan.user.id));
  }
  const afterUsers = users.map((user) =>
    user.id !== target.id
      ? user
      : {
          ...user,
          customSchemas: {
            ...user.customSchemas,
            SarjIdentity: {
              ...user.customSchemas?.SarjIdentity,
              ...change.desired,
            },
          },
        },
  );
  const afterFingerprint =
    await fingerprintGoogleDirectoryAuthority(afterUsers);
  if (afterFingerprint === beforeFingerprint)
    throw new Error(INVALID_TRANSITION);
  return {
    googleUserId: GoogleUserIdSchema.parse(target.id),
    beforeFingerprint,
    afterFingerprint,
  };
}

function indexUsers(users: readonly GoogleDirectoryUser[]) {
  const indexed = new Map<string, GoogleDirectoryUser>();
  for (const user of users) {
    const id = GoogleUserIdSchema.parse(user.id);
    if (indexed.has(id)) throw new Error(INVALID_TRANSITION);
    indexed.set(id, user);
  }
  return indexed;
}

async function assertArtifactBinding(
  plan: ManagedSeed,
  users: ReadonlyMap<string, GoogleDirectoryUser>,
) {
  const updates = await googleIdentityUpdatesFromSeedPlan(plan.artifact);
  assertArtifactSubjects(plan, users);
  if (updates.length !== plan.userPlans.length)
    throw new Error(INVALID_TRANSITION);
  const plannedIds = new Set<string>();
  for (const userPlan of plan.userPlans) {
    if (userPlan.kind === "blocked" || plannedIds.has(userPlan.user.id))
      throw new Error(INVALID_TRANSITION);
    plannedIds.add(userPlan.user.id);
    const update = updates.find(({ userId }) => userId === userPlan.user.id);
    const desired =
      userPlan.kind === "update" ? userPlan.desired : userPlan.identity;
    if (update === undefined || !sameJson(update.desired, desired))
      throw new Error(INVALID_TRANSITION);
  }
}

function assertArtifactSubjects(
  plan: ManagedSeed,
  users: ReadonlyMap<string, GoogleDirectoryUser>,
) {
  const subjects = new Set<string>();
  const targets = new Set<string>();
  const targetLogins = new Set<string>();
  for (const entry of plan.artifact.entries) {
    const user = users.get(entry.subject.googleUserId);
    if (
      user === undefined ||
      !isActiveGoogleDirectoryUser(user) ||
      subjects.has(user.id) ||
      normalizeIdentityEmail(user.primaryEmail) !== entry.subject.primaryEmail
    )
      throw new Error(INVALID_TRANSITION);
    subjects.add(user.id);
    if (entry.kind !== "exact-match") continue;
    if (
      targets.has(entry.target.githubUserId) ||
      targetLogins.has(entry.target.githubLogin) ||
      entry.evidence.githubUserId !== entry.target.githubUserId ||
      entry.evidence.githubLogin !== entry.target.githubLogin
    )
      throw new Error(INVALID_TRANSITION);
    targets.add(entry.target.githubUserId);
    targetLogins.add(entry.target.githubLogin);
  }
  if (
    subjects.size !==
    users.values().filter(isActiveGoogleDirectoryUser).toArray().length
  )
    throw new Error(INVALID_TRANSITION);
}

function assertOriginalUserPlan(
  plan: ExistingUserPlan,
  user: GoogleDirectoryUser | undefined,
) {
  if (
    user?.etag !== plan.user.etag ||
    user.primaryEmail !== plan.user.primaryEmail
  )
    throw new Error(INVALID_TRANSITION);
  const identity = user.customSchemas?.SarjIdentity;
  const current = CURRENT_IDENTITY.parse(
    identity?.githubLogin === undefined && identity?.githubUserId === undefined
      ? null
      : {
          ...(!(identity.githubLogin === undefined) && {
            githubLogin: identity.githubLogin,
          }),
          ...(!(identity.githubUserId === undefined) && {
            githubUserId: identity.githubUserId,
          }),
        },
  );
  const expected = plan.kind === "update" ? plan.current : plan.identity;
  if (
    !sameJson(JsonValueSchema.parse(current), JsonValueSchema.parse(expected))
  )
    throw new Error(INVALID_TRANSITION);
}

function assertEligibleTarget(
  target: GoogleDirectoryUser,
  users: readonly GoogleDirectoryUser[],
) {
  const aliases = [
    ...(target.aliases ?? []),
    ...(target.nonEditableAliases ?? []),
  ];
  if (
    !isActiveGoogleDirectoryUser(target) ||
    orgSyncSettings().protectedDepartedGoogleUserIds.includes(target.id) ||
    protectedIdentityBlocker({
      ...target,
      googleUserId: target.id,
      aliases,
    }) !== undefined
  )
    throw new Error(INVALID_TRANSITION);
  const emails = new Set(
    [target.primaryEmail, ...aliases].map(normalizeIdentityEmail),
  );
  if (
    users.some(
      (user) =>
        user.id !== target.id &&
        [
          user.primaryEmail,
          ...(user.aliases ?? []),
          ...(user.nonEditableAliases ?? []),
        ].some((email) => emails.has(normalizeIdentityEmail(email))),
    )
  )
    throw new Error(INVALID_TRANSITION);
}
