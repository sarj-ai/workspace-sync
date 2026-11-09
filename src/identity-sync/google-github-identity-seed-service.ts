import { z } from "zod";

import type { GitHubIdentitySeedSnapshot } from "../github-access-audit/git-hub-access-audit-client.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import {
  GoogleGitHubIdentityPlanSchema,
  GoogleGithubIdentityApplyMaxProviderReads,
  GoogleGithubIdentityParentApplyMaxProviderReads,
  type GoogleGithubIdentityPlan,
  GoogleGithubIdentitySchema,
  GoogleGithubIdentityService,
  type GoogleWorkspaceIdentityUserGateway,
} from "../org-sync/google-identity-schema.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { mapSequential } from "../runtime/sequential.ts";
import {
  type GitHubIdentitySeedArtifact,
  GitHubIdentitySeedArtifactSchema,
  GitHubIdentitySeedInputError,
  googleIdentityUpdatesFromSeedPlan,
  planGitHubIdentitySeed,
} from "./github-identity-seed-planner.ts";
import type { GoogleIdentityParentContext } from "./google-identity-parent-boundary-schema.ts";
import { normalizeIdentityEmail } from "./normalize-identity-email.ts";

const FingerprintSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const IssueSchema = z.string().trim().min(1).max(300);
const DEFAULT_MAX_PROVIDER_READS = 50;

export const GoogleGitHubIdentitySeedPlanSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("disabled"), reason: IssueSchema }),
  z.strictObject({
    issues: z.array(IssueSchema).min(1),
    kind: z.literal("blocked"),
  }),
  z.strictObject({
    artifact: GitHubIdentitySeedArtifactSchema,
    githubSourceFingerprint: FingerprintSchema,
    kind: z.literal("managed"),
    maxChanges: z.number().int().positive(),
    maxProviderReads: z.number().int().positive(),
    userPlans: z.array(GoogleGitHubIdentityPlanSchema),
  }),
]);
export type GoogleGithubIdentitySeedPlan = z.output<
  typeof GoogleGitHubIdentitySeedPlanSchema
>;

export interface GoogleGithubIdentitySeedSource {
  captureIdentitySeed(): Promise<GitHubIdentitySeedSnapshot>;
}

export interface IGoogleGithubIdentitySeedService {
  applyPlan(
    plan: GoogleGithubIdentitySeedPlan,
    identityBudget?: IdentityWriteBudget,
    parentContext?: GoogleIdentityParentContext<GoogleGithubIdentityPlan>,
  ): Promise<number>;
  capture(
    users: readonly GoogleDirectoryUser[],
    googleAuthorityFingerprint: string,
  ): Promise<GoogleGithubIdentitySeedPlan>;
  readManagedSlice(
    plan: GoogleGithubIdentitySeedPlan,
  ): Promise<ReturnType<typeof JsonValueSchema.parse>>;
}

export interface IGoogleGithubIdentitySeedSourceReader {
  captureSource(): Promise<GitHubIdentitySeedSnapshot>;
}

export class GoogleGithubIdentitySeedService
  implements
    IGoogleGithubIdentitySeedService,
    IGoogleGithubIdentitySeedSourceReader
{
  readonly #github: GoogleGithubIdentitySeedSource;
  readonly #google: GoogleGithubIdentityService;
  readonly #maxChanges: number;
  readonly #maxProviderReads: number;

  constructor(input: {
    github: GoogleGithubIdentitySeedSource;
    google: GoogleWorkspaceIdentityUserGateway;
    maxChanges: number;
    maxProviderReads?: number;
  }) {
    if (!Number.isSafeInteger(input.maxChanges) || input.maxChanges < 1) {
      throw new Error(
        "Google GitHub identity seed maxChanges must be positive",
      );
    }
    this.#github = input.github;
    this.#google = new GoogleGithubIdentityService(input.google);
    this.#maxChanges = input.maxChanges;
    this.#maxProviderReads =
      input.maxProviderReads ?? DEFAULT_MAX_PROVIDER_READS;
    if (
      !Number.isSafeInteger(this.#maxProviderReads) ||
      this.#maxProviderReads < 1
    ) {
      throw new Error(
        "Google GitHub identity seed maxProviderReads must be positive",
      );
    }
  }

  async applyPlan(
    planInput: GoogleGithubIdentitySeedPlan,
    identityBudget?: IdentityWriteBudget,
    parentContext?: GoogleIdentityParentContext<GoogleGithubIdentityPlan>,
  ): Promise<number> {
    const plan = GoogleGitHubIdentitySeedPlanSchema.parse(planInput);
    if (plan.kind !== "managed")
      throw new Error(`Google GitHub identity seed is ${plan.kind}`);
    await googleIdentityUpdatesFromSeedPlan(plan.artifact);
    const changes = plan.userPlans.filter(
      (userPlan) => userPlan.kind === "update",
    );
    if (parentContext !== undefined && changes.length !== 1)
      throw new Error("google_identity_parent_exactly_one_update_required");
    if (changes.length > plan.maxChanges || changes.length > this.#maxChanges) {
      throw new Error("Google GitHub identity seed change cap exceeded");
    }
    this.#assertProviderReadBudget(
      changes.length *
        (parentContext === undefined
          ? GoogleGithubIdentityApplyMaxProviderReads
          : GoogleGithubIdentityParentApplyMaxProviderReads),
      plan.maxProviderReads,
    );
    await mapSequential(changes, (userPlan) =>
      this.#google.applyPlan(userPlan, identityBudget, parentContext),
    );
    return changes.length;
  }

  async capture(
    users: readonly GoogleDirectoryUser[],
    googleAuthorityFingerprint: string,
  ): Promise<GoogleGithubIdentitySeedPlan> {
    const github = await this.#github.captureIdentitySeed();
    if (github.errors.length > 0) {
      return {
        issues: github.errors.map(
          (error) => `GitHub ${error.capability} snapshot unavailable`,
        ),
        kind: "blocked",
      };
    }
    const githubSourceFingerprint =
      await fingerprintGithubIdentitySource(github);
    const evidence = correlateVerifiedEvidence(users, github);
    if (evidence.issues.length > 0)
      return { issues: evidence.issues, kind: "blocked" };
    const activeUsers = users.filter(isActiveGoogleUser);
    let artifact: GitHubIdentitySeedArtifact;
    try {
      artifact = await planGitHubIdentitySeed({
        githubMembers: github.members
          .filter((member) => member.type === "User")
          .map((member) => ({
            githubLogin: member.login,
            githubUserId: String(member.id),
          })),
        googleUsers: activeUsers.map((user) => {
          const displayName = user.name?.fullName?.trim() ?? "";
          return {
            displayName:
              displayName.length === 0 ? user.primaryEmail : displayName,
            ...(evidence.byGoogleUserId.has(user.id) && {
              githubEvidence: evidence.byGoogleUserId.get(user.id),
            }),
            googleUserId: user.id,
            lifecycle: "active" as const,
            primaryEmail: user.primaryEmail,
          };
        }),
        sourceRevision: `${googleAuthorityFingerprint}:${githubSourceFingerprint}`,
      });
    } catch (error) {
      if (error instanceof GitHubIdentitySeedInputError) {
        return {
          issues: ["GitHub identity seed snapshot is ambiguous"],
          kind: "blocked",
        };
      }
      throw error;
    }
    if (artifact.summary.conflicts > 0) {
      return {
        issues: ["GitHub identity seed contains ambiguous mappings"],
        kind: "blocked",
      };
    }
    const updates = await googleIdentityUpdatesFromSeedPlan(artifact);
    const usersById = new Map(activeUsers.map((user) => [user.id, user]));
    const userPlans: GoogleGithubIdentityPlan[] = updates.map((update) => {
      const user = usersById.get(update.userId);
      return this.#google.planFromSnapshot({
        ...update,
        user: user === undefined ? null : googleIdentitySnapshot(user),
      });
    });
    const blocked = userPlans.filter((plan) => plan.kind === "blocked");
    if (blocked.length > 0) {
      return {
        issues: ["A mapped Google identity became inactive or unavailable"],
        kind: "blocked",
      };
    }
    const changes = userPlans.filter((plan) => plan.kind === "update").length;
    if (changes > this.#maxChanges) {
      return {
        issues: [
          `Google GitHub identity seed requires ${String(changes)} changes; cap is ${String(this.#maxChanges)}`,
        ],
        kind: "blocked",
      };
    }
    const requiredProviderReads =
      changes * GoogleGithubIdentityApplyMaxProviderReads;
    if (requiredProviderReads > this.#maxProviderReads) {
      return {
        issues: [
          `Google GitHub identity seed requires ${String(requiredProviderReads)} provider reads; cap is ${String(this.#maxProviderReads)}`,
        ],
        kind: "blocked",
      };
    }
    return GoogleGitHubIdentitySeedPlanSchema.parse({
      artifact,
      githubSourceFingerprint,
      kind: "managed",
      maxChanges: this.#maxChanges,
      maxProviderReads: this.#maxProviderReads,
      userPlans,
    });
  }

  async captureSource(): Promise<GitHubIdentitySeedSnapshot> {
    return this.#github.captureIdentitySeed();
  }

  async readManagedSlice(planInput: GoogleGithubIdentitySeedPlan) {
    const plan = GoogleGitHubIdentitySeedPlanSchema.parse(planInput);
    if (plan.kind !== "managed") return JsonValueSchema.parse([]);
    const changes = plan.userPlans.filter(
      (userPlan) => userPlan.kind === "update",
    );
    this.#assertProviderReadBudget(changes.length, plan.maxProviderReads);
    const current = await mapSequential(changes, (userPlan) =>
      this.#google.plan({
        desired: userPlan.desired,
        userId: userPlan.user.id,
      }),
    );
    return managedSlice(current);
  }

  #assertProviderReadBudget(required: number, reviewedCap: number): void {
    if (required > reviewedCap || required > this.#maxProviderReads) {
      throw new Error("Google GitHub identity seed provider read cap exceeded");
    }
  }
}

export async function fingerprintGithubIdentitySource(
  snapshot: GitHubIdentitySeedSnapshot,
): Promise<string> {
  return sha256Hex(
    JsonValueSchema.parse({
      members: snapshot.members
        .map(({ id, login, type }) => ({ id, login, type }))
        .toSorted((left, right) => left.id - right.id),
      samlExternalIdentities: snapshot.samlExternalIdentities
        .map(({ guid, login, nameId }) => ({ guid, login, nameId }))
        .toSorted((left, right) => left.guid.localeCompare(right.guid)),
    }),
  );
}

export function managedSlice(
  plans: readonly z.output<typeof GoogleGitHubIdentityPlanSchema>[],
) {
  return JsonValueSchema.parse(
    plans
      .filter((plan) => plan.kind !== "blocked")
      .map((plan) => ({
        googleUserId: plan.user.id,
        identity: plan.kind === "update" ? plan.current : plan.identity,
      }))
      .toSorted((left, right) =>
        left.googleUserId.localeCompare(right.googleUserId),
      ),
  );
}

export function desiredManagedSlice(
  plans: readonly z.output<typeof GoogleGitHubIdentityPlanSchema>[],
) {
  return JsonValueSchema.parse(
    plans
      .filter((plan) => plan.kind === "update")
      .map((plan) => ({
        googleUserId: plan.user.id,
        identity: plan.desired,
      }))
      .toSorted((left, right) =>
        left.googleUserId.localeCompare(right.googleUserId),
      ),
  );
}

function correlateVerifiedEvidence(
  users: readonly GoogleDirectoryUser[],
  github: GitHubIdentitySeedSnapshot,
): {
  byGoogleUserId: ReadonlyMap<
    string,
    {
      githubLogin: string;
      githubUserId: string;
      source: "github-enterprise-saml" | "identity-admin";
      verifiedAt: string;
    }
  >;
  issues: string[];
} {
  const activeUsers = users.filter(isActiveGoogleUser);
  const usersByEmail = indexActiveUsersByEmail(activeUsers);
  const { issues, samlByGoogleId } = collectSamlEvidence(usersByEmail, github);
  const byGoogleUserId = new Map();
  for (const user of activeUsers) {
    const resolved = resolveUserEvidence(
      user,
      samlByGoogleId,
      github.capturedAt,
    );
    issues.push(...resolved.issues);
    if (resolved.evidence) byGoogleUserId.set(user.id, resolved.evidence);
  }
  return {
    byGoogleUserId,
    issues: [...new Set(issues)].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    ),
  };
}

interface SamlEvidence {
  githubLogin: string;
  githubUserId: string;
}
type VerifiedEvidence = SamlEvidence & {
  source: "github-enterprise-saml" | "identity-admin";
  verifiedAt: string;
};

function indexActiveUsersByEmail(
  users: readonly GoogleDirectoryUser[],
): Map<string, Map<string, GoogleDirectoryUser>> {
  const usersByEmail = new Map<string, Map<string, GoogleDirectoryUser>>();
  for (const user of users) {
    for (const email of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const normalized = normalizeIdentityEmail(email);
      const matches =
        usersByEmail.get(normalized) ?? new Map<string, GoogleDirectoryUser>();
      matches.set(user.id, user);
      usersByEmail.set(normalized, matches);
    }
  }
  return usersByEmail;
}

function collectSamlEvidence(
  usersByEmail: ReadonlyMap<string, ReadonlyMap<string, GoogleDirectoryUser>>,
  github: GitHubIdentitySeedSnapshot,
): { issues: string[]; samlByGoogleId: Map<string, SamlEvidence[]> } {
  const membersByLogin = new Map(
    github.members.map((member) => [
      member.login.toLocaleLowerCase("en-US"),
      member,
    ]),
  );
  const samlByGoogleId = new Map<string, SamlEvidence[]>();
  const issues: string[] = [];
  for (const identity of github.samlExternalIdentities) {
    if (!(identity.login && identity.nameId)) {
      issues.push("A GitHub SAML identity is incomplete");
      continue;
    }
    const matchedUsers = [
      ...(usersByEmail.get(normalizeIdentityEmail(identity.nameId))?.values() ??
        []),
    ];
    if (matchedUsers.length > 1) {
      issues.push("A GitHub SAML NameID maps to multiple Google identities");
      continue;
    }
    const [user] = matchedUsers;
    if (!user) continue;
    const member = membersByLogin.get(
      identity.login.toLocaleLowerCase("en-US"),
    );
    if (member?.type !== "User") {
      issues.push(
        "A GitHub SAML login has no immutable organization-member identity",
      );
      continue;
    }
    samlByGoogleId.set(user.id, [
      ...(samlByGoogleId.get(user.id) ?? []),
      { githubLogin: member.login, githubUserId: String(member.id) },
    ]);
  }
  return { issues, samlByGoogleId };
}

function resolveUserEvidence(
  user: GoogleDirectoryUser,
  samlByGoogleId: ReadonlyMap<string, readonly SamlEvidence[]>,
  verifiedAt: string,
): { evidence?: VerifiedEvidence; issues: string[] } {
  const current = user.customSchemas?.SarjIdentity;
  const hasLogin = current?.githubLogin !== undefined;
  const hasId = current?.githubUserId !== undefined;
  if (hasLogin !== hasId)
    return { issues: ["A Google SarjIdentity mapping is incomplete"] };
  const uniqueSaml = new Map(
    (samlByGoogleId.get(user.id) ?? []).map((item) => [
      `${item.githubUserId}:${item.githubLogin}`,
      item,
    ]),
  );
  if (uniqueSaml.size > 1) {
    return {
      issues: ["A Google identity maps to multiple GitHub SAML identities"],
    };
  }
  const [samlEvidence] = uniqueSaml.values();
  if (!(current && hasLogin && hasId)) {
    return samlEvidence
      ? {
          evidence: {
            ...samlEvidence,
            source: "github-enterprise-saml",
            verifiedAt,
          },
          issues: [],
        }
      : { issues: [] };
  }
  const currentEvidence = GoogleGithubIdentitySchema.parse(current);
  if (
    samlEvidence &&
    (samlEvidence.githubLogin.toLocaleLowerCase("en-US") !==
      currentEvidence.githubLogin.toLocaleLowerCase("en-US") ||
      samlEvidence.githubUserId !== currentEvidence.githubUserId)
  ) {
    return { issues: ["Google and GitHub SAML identity evidence disagree"] };
  }
  return {
    evidence: {
      githubLogin: currentEvidence.githubLogin,
      githubUserId: currentEvidence.githubUserId,
      source: "identity-admin",
      verifiedAt,
    },
    issues: [],
  };
}

function isActiveGoogleUser(user: GoogleDirectoryUser): boolean {
  return (
    user.suspended !== true &&
    user.archived !== true &&
    user.deletionTime === undefined
  );
}

function googleIdentitySnapshot(user: GoogleDirectoryUser) {
  return {
    archived: user.archived,
    customSchemas: user.customSchemas,
    deletionTime: user.deletionTime,
    etag: user.etag,
    id: user.id,
    primaryEmail: user.primaryEmail,
    suspended: user.suspended,
  };
}
