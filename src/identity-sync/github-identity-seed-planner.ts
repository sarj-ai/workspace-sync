import { z } from "zod";

import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
  GoogleUserIdSchema,
  PrimaryEmailSchema,
} from "../catalog/identity-authority.ts";

const NonBlankTextSchema = z.string().trim().min(1);
const IsoInstantSchema = z.iso.datetime({ offset: true });
const JsonRecordSchema = z.record(z.string(), z.unknown());

const VerifiedGitHubEvidenceSchema = z
  .strictObject({
    githubLogin: GitHubLoginSchema,
    githubUserId: GitHubUserIdSchema,
    source: z.enum(["github-enterprise-saml", "identity-admin"]),
    verifiedAt: IsoInstantSchema,
  })
  .readonly();

const GoogleIdentitySeedUserSchema = z
  .strictObject({
    displayName: NonBlankTextSchema,
    githubEvidence: VerifiedGitHubEvidenceSchema.optional(),
    googleUserId: GoogleUserIdSchema,
    lifecycle: z.enum(["active", "archived", "deleted", "suspended"]),
    primaryEmail: PrimaryEmailSchema,
  })
  .readonly();

const GitHubOrganizationMemberSchema = z
  .strictObject({
    email: PrimaryEmailSchema.optional(),
    githubLogin: GitHubLoginSchema,
    githubUserId: GitHubUserIdSchema,
    name: NonBlankTextSchema.optional(),
  })
  .readonly();

export const GitHubIdentitySeedInputSchema = z
  .strictObject({
    githubMembers: z.array(GitHubOrganizationMemberSchema).readonly(),
    googleUsers: z.array(GoogleIdentitySeedUserSchema).readonly(),
    sourceRevision: NonBlankTextSchema,
  })
  .readonly();

const IdentitySeedSubjectSchema = z
  .strictObject({
    displayName: NonBlankTextSchema,
    googleUserId: GoogleUserIdSchema,
    primaryEmail: PrimaryEmailSchema,
  })
  .readonly();

const IdentitySeedTargetSchema = z
  .strictObject({
    githubLogin: GitHubLoginSchema,
    githubUserId: GitHubUserIdSchema,
  })
  .readonly();
const ConflictCandidatesSchema = z
  .tuple([IdentitySeedTargetSchema, IdentitySeedTargetSchema])
  .rest(IdentitySeedTargetSchema)
  .readonly();

const ExactMatchSchema = z
  .strictObject({
    evidence: VerifiedGitHubEvidenceSchema,
    kind: z.literal("exact-match"),
    subject: IdentitySeedSubjectSchema,
    target: IdentitySeedTargetSchema,
  })
  .readonly();

const UnresolvedMatchSchema = z
  .strictObject({
    candidates: z.array(IdentitySeedTargetSchema).readonly(),
    kind: z.literal("unresolved"),
    reason: z.enum([
      "github-member-not-found",
      "missing-verified-evidence",
      "unverified-heuristic",
    ]),
    subject: IdentitySeedSubjectSchema,
  })
  .readonly();

const ConflictMatchSchema = z
  .strictObject({
    candidates: ConflictCandidatesSchema,
    kind: z.literal("conflict"),
    reason: z.enum(["ambiguous-heuristic", "evidence-id-login-mismatch"]),
    subject: IdentitySeedSubjectSchema,
  })
  .readonly();

export const GitHubIdentitySeedEntrySchema = z.discriminatedUnion("kind", [
  ExactMatchSchema,
  UnresolvedMatchSchema,
  ConflictMatchSchema,
]);

const GitHubIdentitySeedArtifactBodyShape = {
  entries: z.array(GitHubIdentitySeedEntrySchema).readonly(),
  schemaVersion: z.literal("github-identity-seed-plan/v1"),
  sourceRevision: NonBlankTextSchema,
  summary: z
    .strictObject({
      conflicts: z.number().int().nonnegative(),
      exactMatches: z.number().int().nonnegative(),
      unresolved: z.number().int().nonnegative(),
    })
    .readonly(),
} as const;

const GitHubIdentitySeedArtifactBodySchema = z
  .strictObject(GitHubIdentitySeedArtifactBodyShape)
  .superRefine(validateSummary)
  .readonly();

export const GitHubIdentitySeedArtifactSchema = z
  .strictObject({
    ...GitHubIdentitySeedArtifactBodyShape,
    contentHash: z
      .string()
      .regex(/^[a-f0-9]{64}$/u)
      .brand<"GitHubIdentitySeedContentHash">(),
  })
  .superRefine(validateSummary)
  .readonly();

export type GitHubIdentitySeedInput = z.output<
  typeof GitHubIdentitySeedInputSchema
>;
export type GitHubIdentitySeedEntry = z.output<
  typeof GitHubIdentitySeedEntrySchema
>;
export type GitHubIdentitySeedArtifact = z.output<
  typeof GitHubIdentitySeedArtifactSchema
>;

export interface GoogleIdentitySeedSource {
  listIdentitySeedUsers(): Promise<unknown>;
}

export interface GitHubOrganizationMemberSource {
  listOrganizationMembers(): Promise<unknown>;
}

export interface GitHubIdentitySeedSources {
  readonly github: GitHubOrganizationMemberSource;
  readonly google: GoogleIdentitySeedSource;
  sourceRevision(): Promise<string>;
}

export interface IGitHubIdentitySeedPlanningService {
  plan(): Promise<GitHubIdentitySeedArtifact>;
}

export interface GoogleGithubIdentitySeedUpdate {
  readonly desired: {
    readonly githubLogin: z.output<typeof GitHubLoginSchema>;
    readonly githubUserId: z.output<typeof GitHubUserIdSchema>;
  };
  readonly userId: z.output<typeof GoogleUserIdSchema>;
}

export class GitHubIdentitySeedInputError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[], options?: ErrorOptions) {
    super(`GitHub identity seed input rejected: ${issues.join("; ")}`, options);
    this.name = "GitHubIdentitySeedInputError";
    this.issues = issues;
  }
}

export class GitHubIdentitySeedPlanningService implements IGitHubIdentitySeedPlanningService {
  readonly #sources: GitHubIdentitySeedSources;

  constructor(sources: GitHubIdentitySeedSources) {
    this.#sources = sources;
  }

  async plan(): Promise<GitHubIdentitySeedArtifact> {
    const [googleUsers, githubMembers, sourceRevision] = await Promise.all([
      this.#sources.google.listIdentitySeedUsers(),
      this.#sources.github.listOrganizationMembers(),
      this.#sources.sourceRevision(),
    ]);
    return planGitHubIdentitySeed({
      githubMembers,
      googleUsers,
      sourceRevision,
    });
  }
}

export async function planGitHubIdentitySeed(
  input: unknown,
): Promise<GitHubIdentitySeedArtifact> {
  const snapshot = GitHubIdentitySeedInputSchema.parse(input);
  assertSeedSnapshotIsSafe(snapshot);

  const membersById = new Map(
    snapshot.githubMembers.map((member) => [member.githubUserId, member]),
  );
  const membersByLogin = new Map(
    snapshot.githubMembers.map((member) => [member.githubLogin, member]),
  );
  const entries = snapshot.googleUsers
    .map((user) =>
      planUser(user, snapshot.githubMembers, membersById, membersByLogin),
    )
    .toSorted((left, right) =>
      left.subject.googleUserId.localeCompare(right.subject.googleUserId),
    );
  const body = GitHubIdentitySeedArtifactBodySchema.parse({
    entries,
    schemaVersion: "github-identity-seed-plan/v1",
    sourceRevision: snapshot.sourceRevision,
    summary: {
      conflicts: entries.filter((entry) => entry.kind === "conflict").length,
      exactMatches: entries.filter((entry) => entry.kind === "exact-match")
        .length,
      unresolved: entries.filter((entry) => entry.kind === "unresolved").length,
    },
  });
  return GitHubIdentitySeedArtifactSchema.parse({
    ...body,
    contentHash: await sha256(canonicalJson(body)),
  });
}

export async function googleIdentityUpdatesFromSeedPlan(
  artifact: unknown,
): Promise<readonly GoogleGithubIdentitySeedUpdate[]> {
  const parsed = await verifyGitHubIdentitySeedArtifact(artifact);
  if (parsed.entries.some((entry) => entry.kind === "conflict")) {
    throw new GitHubIdentitySeedInputError([
      "conflicted seed plans cannot feed Google updates",
    ]);
  }
  return parsed.entries.flatMap((entry) =>
    entry.kind === "exact-match"
      ? {
          desired: {
            githubLogin: entry.target.githubLogin,
            githubUserId: entry.target.githubUserId,
          },
          userId: entry.subject.googleUserId,
        }
      : [],
  );
}

export async function verifyGitHubIdentitySeedArtifact(
  artifact: unknown,
): Promise<GitHubIdentitySeedArtifact> {
  const parsed = GitHubIdentitySeedArtifactSchema.parse(artifact);
  const { contentHash, ...body } = parsed;
  const expectedHash = await sha256(canonicalJson(body));
  if (contentHash !== expectedHash) {
    throw new GitHubIdentitySeedInputError([
      "seed plan content hash does not match its body",
    ]);
  }
  return parsed;
}

function assertSeedSnapshotIsSafe(snapshot: GitHubIdentitySeedInput): void {
  const evidence = snapshot.googleUsers.flatMap((user) =>
    user.githubEvidence === undefined ? [] : [user.githubEvidence],
  );
  const issues = [
    ...duplicateIssues(
      snapshot.googleUsers.map((user) => user.googleUserId),
      "Google user ID",
    ),
    ...duplicateIssues(
      snapshot.googleUsers.map((user) => user.primaryEmail),
      "Google primary email",
    ),
    ...duplicateIssues(
      snapshot.githubMembers.map((member) => member.githubUserId),
      "GitHub user ID",
    ),
    ...duplicateIssues(
      snapshot.githubMembers.map((member) => member.githubLogin),
      "GitHub login",
    ),
    ...duplicateIssues(
      evidence.map((item) => item.githubUserId),
      "verified GitHub user ID",
    ),
    ...duplicateIssues(
      evidence.map((item) => item.githubLogin),
      "verified GitHub login",
    ),
    ...snapshot.googleUsers
      .filter((user) => user.lifecycle !== "active")
      .map((user) => `Google user ${user.googleUserId} is ${user.lifecycle}`),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  if (issues.length > 0) throw new GitHubIdentitySeedInputError(issues);
}

function duplicateIssues(
  values: readonly unknown[],
  label: string,
): readonly string[] {
  const counts = new Map<unknown, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return counts
    .entries()
    .filter(([, count]) => count > 1)
    .map(([value]) => `duplicate ${label}: ${String(value)}`)
    .toArray();
}

function planUser(
  user: GitHubIdentitySeedInput["googleUsers"][number],
  members: GitHubIdentitySeedInput["githubMembers"],
  membersById: ReadonlyMap<
    string,
    GitHubIdentitySeedInput["githubMembers"][number]
  >,
  membersByLogin: ReadonlyMap<
    string,
    GitHubIdentitySeedInput["githubMembers"][number]
  >,
): GitHubIdentitySeedEntry {
  const subject = {
    displayName: user.displayName,
    googleUserId: user.googleUserId,
    primaryEmail: user.primaryEmail,
  };
  if (user.githubEvidence) {
    const byId = membersById.get(user.githubEvidence.githubUserId);
    const byLogin = membersByLogin.get(user.githubEvidence.githubLogin);
    if (byId && byLogin && byId === byLogin) {
      return {
        evidence: user.githubEvidence,
        kind: "exact-match",
        subject,
        target: targetOf(byId),
      };
    }
    const candidates = uniqueTargets([byId, byLogin].filter(isDefined));
    if (candidates.length === 0) {
      return {
        candidates,
        kind: "unresolved",
        reason: "github-member-not-found",
        subject,
      };
    }
    const desired = {
      githubLogin: user.githubEvidence.githubLogin,
      githubUserId: user.githubEvidence.githubUserId,
    };
    const combined = new Map(
      candidates.map((candidate) => [JSON.stringify(candidate), candidate]),
    );
    combined.set(JSON.stringify(desired), desired);
    const conflictCandidates = combined
      .values()
      .toArray()
      .toSorted((left, right) =>
        `${left.githubUserId}:${left.githubLogin}`.localeCompare(
          `${right.githubUserId}:${right.githubLogin}`,
        ),
      );
    return {
      candidates: ConflictCandidatesSchema.parse(conflictCandidates),
      kind: "conflict",
      reason: "evidence-id-login-mismatch",
      subject,
    };
  }

  const heuristicCandidates = uniqueTargets(
    members.filter(
      (member) =>
        member.email === user.primaryEmail ||
        normalizeName(member.name) === normalizeName(user.displayName),
    ),
  );
  if (heuristicCandidates.length > 1) {
    return {
      candidates: ConflictCandidatesSchema.parse(heuristicCandidates),
      kind: "conflict",
      reason: "ambiguous-heuristic",
      subject,
    };
  }
  return {
    candidates: heuristicCandidates,
    kind: "unresolved",
    reason:
      heuristicCandidates.length === 1
        ? "unverified-heuristic"
        : "missing-verified-evidence",
    subject,
  };
}

function targetOf(
  member: GitHubIdentitySeedInput["githubMembers"][number],
): z.output<typeof IdentitySeedTargetSchema> {
  return { githubLogin: member.githubLogin, githubUserId: member.githubUserId };
}

function uniqueTargets(
  members: readonly GitHubIdentitySeedInput["githubMembers"][number][],
): z.output<typeof IdentitySeedTargetSchema>[] {
  return new Map(
    members.map((member) => [member.githubUserId, targetOf(member)]),
  )
    .values()
    .toArray()
    .toSorted((left, right) =>
      left.githubUserId.localeCompare(right.githubUserId),
    );
}

function normalizeName(value: string | undefined): string | undefined {
  return value
    ?.trim()
    .toLocaleLowerCase("en-US")
    .replaceAll(/[^a-z0-9]/gu, "");
}

function isDefined<Value>(value: undefined | Value): value is Value {
  return value !== undefined;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = JsonRecordSchema.safeParse(value);
  if (object.success) {
    return `{${Object.entries(object.data)
      .filter(([, child]) => child !== undefined)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function validateSummary(
  artifact: {
    readonly entries: readonly GitHubIdentitySeedEntry[];
    readonly summary: {
      readonly conflicts: number;
      readonly exactMatches: number;
      readonly unresolved: number;
    };
  },
  context: z.core.$RefinementCtx,
): void {
  const expected = {
    conflicts: artifact.entries.filter((entry) => entry.kind === "conflict")
      .length,
    exactMatches: artifact.entries.filter(
      (entry) => entry.kind === "exact-match",
    ).length,
    unresolved: artifact.entries.filter((entry) => entry.kind === "unresolved")
      .length,
  };
  for (const key of ["conflicts", "exactMatches", "unresolved"] as const) {
    if (artifact.summary[key] !== expected[key]) {
      context.addIssue({
        code: "custom",
        message: `${key} must equal the number of matching entries`,
        path: ["summary", key],
      });
    }
  }
}
