import { dequal } from "dequal";
import { z } from "zod";

import {
  GitHubLoginSchema,
  GoogleUserIdSchema,
  PrimaryEmailSchema,
} from "../catalog/identity-authority.ts";
import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import {
  GoogleGitHubIdentityPlanSchema,
  type GoogleGithubIdentityPlan,
  GoogleGithubIdentitySchema,
  GoogleGithubIdentityService,
  GoogleIdentityUserSnapshotSchema,
  type GoogleWorkspaceIdentityUserGateway,
  type SarjIdentitySchemaService,
} from "../org-sync/google-identity-schema.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import { mapSequential } from "../runtime/sequential.ts";
import {
  type GoogleIdentityAttestationGuard,
  type GoogleIdentityMaintenanceFence,
  GoogleIdentityMaintenanceFenceError,
} from "./google-identity-maintenance-fence-error.ts";

type ApplyResult = Promise<{
  applied: number;
  planHash: string;
  verified: true;
}>;
type ReadObservedIdentityResult =
  | { kind: "invalid" }
  | { kind: "linked"; identity: z.output<typeof GoogleGithubIdentitySchema> }
  | { kind: "unlinked" };

const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_API_VERSION = "2022-11-28";
const GITHUB_REQUEST_TIMEOUT_MS = 15_000;
const PlanHashSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const AdminActorIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .brand<"AdminActorId">();

const GitHubIdentityAttestationSubjectSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    googleUserId: GoogleUserIdSchema,
    kind: z.literal("google-user-id"),
  }),
  z.strictObject({
    kind: z.literal("primary-email"),
    primaryEmail: PrimaryEmailSchema,
  }),
]);

const GITHUB_IDENTITY_ADMIN_ATTESTATION_INPUT_SHAPE = {
  githubLogin: GitHubLoginSchema,
  subject: GitHubIdentityAttestationSubjectSchema,
} as const;

export const GitHubIdentityAdminAttestationSchema = z
  .strictObject({
    ...GITHUB_IDENTITY_ADMIN_ATTESTATION_INPUT_SHAPE,
    attestedAt: z.iso.datetime({ offset: true }),
    attestedBy: AdminActorIdSchema,
  })
  .readonly();

const GitHubIdentityAdminAttestationInputSchema = z
  .strictObject(GITHUB_IDENTITY_ADMIN_ATTESTATION_INPUT_SHAPE)
  .readonly();

export const GitHubIdentityAdminAttestationRequestSchema = z
  .strictObject({
    attestations: z
      .array(GitHubIdentityAdminAttestationInputSchema)
      .length(1)
      .readonly(),
    schemaVersion: z.literal("github-identity-admin-attestation/v1"),
  })
  .readonly();

const ResolvedGitHubIdentitySchema = z
  .object({ id: z.number().int().positive(), login: GitHubLoginSchema })
  .transform(({ id, login }) =>
    GoogleGithubIdentitySchema.parse({
      githubLogin: login,
      githubUserId: String(id),
    }),
  )
  .readonly();

const NonBlockedGoogleGitHubIdentityPlanSchema = z.union([
  GoogleGitHubIdentityPlanSchema.options[1],
  GoogleGitHubIdentityPlanSchema.options[2],
]);

const GitHubIdentityAdminAttestationPlanEntrySchema = z
  .strictObject({
    attestation: GitHubIdentityAdminAttestationSchema,
    googlePlan: NonBlockedGoogleGitHubIdentityPlanSchema,
    target: GoogleGithubIdentitySchema,
  })
  .readonly();

const GitHubIdentityAdminAttestationPlanBodySchema = z
  .strictObject({
    entries: z
      .array(GitHubIdentityAdminAttestationPlanEntrySchema)
      .length(1)
      .readonly(),
    schemaVersion: z.literal("github-identity-admin-attestation-plan/v1"),
  })
  .readonly();

export const GitHubIdentityAdminAttestationPlanSchema = z
  .strictObject({
    entries: z
      .array(GitHubIdentityAdminAttestationPlanEntrySchema)
      .length(1)
      .readonly(),
    planHash: PlanHashSchema,
    schemaVersion: z.literal("github-identity-admin-attestation-plan/v1"),
  })
  .readonly();

export type GitHubIdentityAdminAttestationPlan = z.output<
  typeof GitHubIdentityAdminAttestationPlanSchema
>;

const GitHubIdentityAdminAttestationContextSchema = z
  .strictObject({
    actorId: AdminActorIdSchema,
    attestedAt: z.iso.datetime({ offset: true }),
  })
  .readonly();
export type GitHubIdentityAdminAttestationContext = z.input<
  typeof GitHubIdentityAdminAttestationContextSchema
>;

export interface GitHubIdentityResolver {
  resolveUser(login: z.output<typeof GitHubLoginSchema>): Promise<unknown>;
}

export interface GoogleIdentityAttestationDirectory extends GoogleWorkspaceIdentityUserGateway {
  listIdentityUsers(): Promise<readonly unknown[]>;
}

export interface IGitHubIdentityAdminAttestationService {
  apply(planInput: unknown, confirmPlanHash: string): ApplyResult;
  plan(
    requestInput: unknown,
    contextInput: GitHubIdentityAdminAttestationContext,
  ): Promise<GitHubIdentityAdminAttestationPlan>;
}

export class GitHubIdentityAdminAttestationError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[], options?: ErrorOptions) {
    const ordered = [...new Set(issues)].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    );
    super(
      `GitHub identity admin attestation rejected: ${ordered.join("; ")}`,
      options,
    );
    this.name = "GitHubIdentityAdminAttestationError";
    this.issues = ordered;
  }
}

type GitHubIdentityLookupFailure =
  | "authentication"
  | "forbidden"
  | "invalid-response"
  | "network"
  | "not-found"
  | "rate-limited"
  | "request-construction"
  | "runtime"
  | "timeout"
  | "unexpected-status"
  | "upstream";

export type GitHubIdentityAdminAttestationSource =
  | "github-user-lookup"
  | "google-directory-list"
  | "google-directory-schema"
  | "google-directory-user"
  | `github-user-lookup.${GitHubIdentityLookupFailure}`;

/** Identifies the failed provider boundary without exposing provider payloads or employee data. */
export class GitHubIdentityAdminAttestationSourceError extends Error {
  readonly source: GitHubIdentityAdminAttestationSource;

  constructor(
    source: GitHubIdentityAdminAttestationSource,
    options?: ErrorOptions,
  ) {
    super(`GitHub identity attestation provider failed at ${source}.`, options);
    this.name = "GitHubIdentityAdminAttestationSourceError";
    this.source = source;
  }
}

class GitHubIdentityLookupNotFoundError extends Error {
  constructor() {
    super("GitHub login does not resolve.");
    this.name = "GitHubIdentityLookupNotFoundError";
  }
}

/** Read-only lookup used to bind a reviewed login to GitHub's immutable numeric user ID. */
export class GitHubIdentityLookupClient implements GitHubIdentityResolver {
  readonly #fetch: typeof fetch;
  readonly #token: string;

  constructor(input: { fetchImpl?: typeof fetch; token: string }) {
    this.#fetch = fetchPort(input.fetchImpl ?? runtimeFetch);
    this.#token = input.token;
  }

  async resolveUser(loginInput: string): Promise<unknown> {
    const login = GitHubLoginSchema.parse(loginInput);
    const url = `${GITHUB_API_BASE}/users/${encodeURIComponent(login)}`;
    let requestInit: RequestInit;
    try {
      requestInit = {
        headers: new Headers({
          accept: "application/vnd.github+json",
          authorization: `Bearer ${this.#token}`,
          "user-agent": "workspace-sync-github-identity-attestation",
          "x-github-api-version": GITHUB_API_VERSION,
        }),
        signal: AbortSignal.timeout(GITHUB_REQUEST_TIMEOUT_MS),
      };
    } catch (error) {
      throw githubLookupSourceError("request-construction", error);
    }
    let response: Response;
    try {
      response = await this.#fetch(url, requestInit);
    } catch (error) {
      throw githubLookupSourceError(githubLookupTransportFailure(error), error);
    }
    if (!response.ok) {
      await discardResponseBody(response);
      const failure = githubLookupFailureForResponse(response);
      if (failure === "not-found")
        throw new GitHubIdentityLookupNotFoundError();
      throw githubLookupSourceError(failure);
    }
    try {
      return await response.json();
    } catch (error) {
      throw githubLookupSourceError("invalid-response", error);
    }
  }
}

function githubLookupTransportFailure(
  error: unknown,
): Extract<GitHubIdentityLookupFailure, "network" | "runtime" | "timeout"> {
  if (
    error instanceof Error &&
    (error.name === "AbortError" || error.name === "TimeoutError")
  ) {
    return "timeout";
  }
  return error instanceof TypeError ? "network" : "runtime";
}

async function discardResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The reviewed status classification takes precedence over transport cleanup failure.
  }
}

function githubLookupFailureForResponse(
  response: Response,
): GitHubIdentityLookupFailure {
  if (response.status === 401) return "authentication";
  if (
    response.status === 429 ||
    (response.status === 403 &&
      (response.headers.get("retry-after") !== null ||
        response.headers.get("x-ratelimit-remaining") === "0"))
  ) {
    return "rate-limited";
  }
  if (response.status === 403) return "forbidden";
  if (response.status === 404) return "not-found";
  if (response.status >= 500) return "upstream";
  return "unexpected-status";
}

function githubLookupSourceError(
  failure: GitHubIdentityLookupFailure,
  cause?: unknown,
): GitHubIdentityAdminAttestationSourceError {
  return new GitHubIdentityAdminAttestationSourceError(
    `github-user-lookup.${failure}`,
    {
      ...(!(cause === undefined) && { cause }),
    },
  );
}

/**
 * Converts explicit administrator attestations into exact, replay-safe Google identity updates.
 * It never guesses from names, emails, commit metadata, or public GitHub profile fields.
 */
export class GitHubIdentityAdminAttestationService implements IGitHubIdentityAdminAttestationService {
  readonly #github: GitHubIdentityResolver;
  readonly #google: GoogleIdentityAttestationDirectory;
  readonly #identity: GoogleGithubIdentityService;
  readonly #schema: Pick<SarjIdentitySchemaService, "plan">;
  readonly #maintenanceFence:
    | GoogleIdentityMaintenanceFence<GitHubIdentityAdminAttestationPlan>
    | undefined;

  constructor(input: {
    github: GitHubIdentityResolver;
    google: GoogleIdentityAttestationDirectory;
    schema: Pick<SarjIdentitySchemaService, "plan">;
    maintenanceFence?: GoogleIdentityMaintenanceFence<GitHubIdentityAdminAttestationPlan>;
  }) {
    this.#github = input.github;
    this.#google = input.google;
    this.#identity = new GoogleGithubIdentityService(input.google);
    this.#schema = input.schema;
    this.#maintenanceFence = input.maintenanceFence;
  }

  async plan(
    requestInput: unknown,
    contextInput: GitHubIdentityAdminAttestationContext,
  ): Promise<GitHubIdentityAdminAttestationPlan> {
    const request =
      GitHubIdentityAdminAttestationRequestSchema.parse(requestInput);
    const context =
      GitHubIdentityAdminAttestationContextSchema.parse(contextInput);
    await this.#assertSchemaCompatible();
    const users = await readAttestationSource(
      "google-directory-list",
      async () => parseDirectoryUsers(await this.#google.listIdentityUsers()),
    );
    const resolved = await mapSequential(
      request.attestations,
      async (input) => {
        const attestation = GitHubIdentityAdminAttestationSchema.parse({
          ...input,
          attestedAt: context.attestedAt,
          attestedBy: context.actorId,
        });
        return {
          attestation,
          target: await readAttestationSource("github-user-lookup", async () =>
            ResolvedGitHubIdentitySchema.parse(
              await this.#github.resolveUser(attestation.githubLogin),
            ),
          ),
        };
      },
    );
    const entries = await mapSequential(
      resolved,
      async ({ attestation, target }) => {
        const user = resolveGoogleSubject(attestation, users);
        const exactUser = await readAttestationSource(
          "google-directory-user",
          () => this.#readExactGoogleUser(user.id),
        );
        const googlePlan = this.#identity.planFromSnapshot({
          desired: target,
          user: exactUser,
          userId: user.id,
        });
        if (googlePlan.kind === "blocked") {
          throw new GitHubIdentityAdminAttestationError([
            `Google user ${user.id} is ${googlePlan.reason}`,
          ]);
        }
        return { attestation, googlePlan, target };
      },
    );
    assertResolvedMappingsAreSafe(entries, users);
    const body = GitHubIdentityAdminAttestationPlanBodySchema.parse({
      entries: entries.toSorted((left, right) =>
        left.googlePlan.user.id.localeCompare(right.googlePlan.user.id),
      ),
      schemaVersion: "github-identity-admin-attestation-plan/v1",
    });
    return GitHubIdentityAdminAttestationPlanSchema.parse({
      ...body,
      planHash: await sha256Hex(JsonValueSchema.parse(body)),
    });
  }

  async apply(planInput: unknown, confirmPlanHash: string): ApplyResult {
    const plan = await verifyPlan(planInput, confirmPlanHash);
    if (this.#maintenanceFence === undefined)
      throw new GoogleIdentityMaintenanceFenceError();
    return this.#maintenanceFence.withFence((guard) =>
      this.#applyFenced(plan, guard),
    );
  }

  async #applyFenced(
    plan: GitHubIdentityAdminAttestationPlan,
    guard: GoogleIdentityAttestationGuard<GitHubIdentityAdminAttestationPlan>,
  ): ApplyResult {
    await this.#assertSchemaCompatible();
    const users = await readAttestationSource(
      "google-directory-list",
      async () => parseDirectoryUsers(await this.#google.listIdentityUsers()),
    );
    const refreshedEntries = await mapSequential(
      plan.entries,
      async (entry) => {
        const target = await readAttestationSource(
          "github-user-lookup",
          async () =>
            ResolvedGitHubIdentitySchema.parse(
              await this.#github.resolveUser(entry.target.githubLogin),
            ),
        );
        if (!sameIdentity(target, entry.target)) {
          throw new GitHubIdentityAdminAttestationError([
            `GitHub identity ${entry.target.githubLogin} drifted after PLAN`,
          ]);
        }
        const user = resolveGoogleSubject(entry.attestation, users);
        if (user.id !== entry.googlePlan.user.id) {
          throw new GitHubIdentityAdminAttestationError([
            `Google subject for ${entry.target.githubLogin} drifted after PLAN`,
          ]);
        }
        const exactUser = await readAttestationSource(
          "google-directory-user",
          () => this.#readExactGoogleUser(user.id),
        );
        const currentPlan = this.#identity.planFromSnapshot({
          desired: entry.target,
          user: exactUser,
          userId: user.id,
        });
        if (currentPlan.kind === "blocked") {
          throw new GitHubIdentityAdminAttestationError([
            `Google user ${user.id} is ${currentPlan.reason}`,
          ]);
        }
        if (!compatibleWithReviewedPlan(entry.googlePlan, currentPlan)) {
          throw new GitHubIdentityAdminAttestationError([
            `Google identity ${user.id} drifted after PLAN`,
          ]);
        }
        return { ...entry, currentPlan };
      },
    );
    assertResolvedMappingsAreSafe(refreshedEntries, users);
    const pending = refreshedEntries.filter(
      ({ currentPlan }) => currentPlan.kind === "update",
    );
    let attemptId: string | undefined;
    const planExpiresAtMs = Math.min(
      ...plan.entries.map(
        (entry) => Date.parse(entry.attestation.attestedAt) + 600_000,
      ),
    );
    const deadlineAtMs = Math.min(guard.deadlineAtMs, planExpiresAtMs);
    const writer = new GoogleGithubIdentityService({
      readUserById: (id) => this.#google.readUserById(id, guard.deadlineAtMs),
      updateUser: async (input) => {
        await guard.assertWriteAuthority();
        await this.#google.updateUser({
          ...input,
          maintenanceGuard: {
            deadlineAtMs,
            assertWriteAuthority: () =>
              guard.assertWriteAuthority(planExpiresAtMs),
            beforeDispatch: async () => {
              await this.#assertSchemaCompatible();
              await guard.assertWriteAuthority(planExpiresAtMs);
              attemptId = await guard.beginAttempt(plan);
            },
          },
        });
      },
    });
    await mapSequential(pending, ({ googlePlan }) =>
      writer.applyPlan(googlePlan),
    );
    if (attemptId !== undefined) {
      const entry = plan.entries[0];
      if (entry === undefined) throw new GoogleIdentityMaintenanceFenceError();
      await guard.resolveAttempt(
        attemptId,
        await this.#google.readUserById(
          entry.googlePlan.user.id,
          guard.deadlineAtMs,
        ),
      );
    }
    return { applied: pending.length, planHash: plan.planHash, verified: true };
  }

  async #assertSchemaCompatible(): Promise<void> {
    const schema = await readAttestationSource("google-directory-schema", () =>
      this.#schema.plan(),
    );
    if (schema.kind !== "unchanged") {
      throw new GitHubIdentityAdminAttestationError([
        "SarjIdentity schema must already be compatible",
      ]);
    }
  }

  async #readExactGoogleUser(
    googleUserId: string,
  ): Promise<null | z.output<typeof GoogleIdentityUserSnapshotSchema>> {
    const snapshot = await this.#google.readUserById(googleUserId);
    if (snapshot === null) return null;
    const user = GoogleIdentityUserSnapshotSchema.strip().parse(snapshot);
    if (user.id !== googleUserId) {
      throw new Error("Google Directory returned the wrong immutable user ID");
    }
    return user;
  }
}

async function readAttestationSource<T>(
  source: GitHubIdentityAdminAttestationSource,
  read: () => Promise<T>,
): Promise<T> {
  try {
    return await read();
  } catch (error) {
    if (error instanceof GitHubIdentityLookupNotFoundError) {
      throw new GitHubIdentityAdminAttestationError(
        ["GitHub login does not resolve"],
        {
          cause: error,
        },
      );
    }
    if (
      error instanceof GitHubIdentityAdminAttestationError ||
      error instanceof GitHubIdentityAdminAttestationSourceError
    ) {
      throw error;
    }
    throw new GitHubIdentityAdminAttestationSourceError(source, {
      cause: error,
    });
  }
}

async function verifyPlan(
  planInput: unknown,
  confirmPlanHash: string,
): Promise<GitHubIdentityAdminAttestationPlan> {
  const plan = GitHubIdentityAdminAttestationPlanSchema.parse(planInput);
  const { planHash, ...body } = plan;
  const expected = await sha256Hex(
    JsonValueSchema.parse(
      GitHubIdentityAdminAttestationPlanBodySchema.parse(body),
    ),
  );
  if (planHash !== expected) {
    throw new GitHubIdentityAdminAttestationError([
      "plan content hash does not match its body",
    ]);
  }
  if (PlanHashSchema.parse(confirmPlanHash) !== planHash) {
    throw new GitHubIdentityAdminAttestationError([
      "confirmed plan hash does not match",
    ]);
  }
  return plan;
}

function parseDirectoryUsers(users: readonly unknown[]) {
  const parsed = users.map((user) =>
    GoogleIdentityUserSnapshotSchema.strip().parse(user),
  );
  const issues = [
    ...duplicateValues(
      parsed.map(({ id }) => id),
      "Google user ID",
    ),
    ...duplicateValues(
      parsed.map(({ primaryEmail }) => primaryEmail.toLowerCase()),
      "Google primary email",
    ),
  ];
  if (issues.length > 0) {
    throw new Error(
      "Google Directory identity snapshot violates its uniqueness contract",
    );
  }
  return parsed;
}

function assertResolvedMappingsAreSafe(
  entries: readonly {
    googlePlan: Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>;
    target: z.output<typeof GoogleGithubIdentitySchema>;
  }[],
  users: ReturnType<typeof parseDirectoryUsers>,
): void {
  const issues = [
    ...duplicateValues(
      entries.map(({ googlePlan }) => googlePlan.user.id),
      "resolved Google user ID",
    ),
    ...duplicateValues(
      entries.map(({ target }) => target.githubUserId),
      "resolved GitHub user ID",
    ),
    ...duplicateValues(
      entries.map(({ target }) => target.githubLogin),
      "resolved GitHub login",
    ),
  ];
  const desiredByGoogleId = new Map(
    entries.map((entry) => [entry.googlePlan.user.id, entry.target]),
  );
  for (const user of users) {
    const current = readObservedIdentity(user);
    if (current.kind === "invalid") {
      issues.push(
        `Google user ${user.id} has an incomplete or invalid GitHub identity`,
      );
      continue;
    }
    if (current.kind === "unlinked") continue;
    for (const [desiredGoogleId, desired] of desiredByGoogleId) {
      if (desiredGoogleId === user.id) continue;
      if (
        current.identity.githubUserId === desired.githubUserId ||
        current.identity.githubLogin === desired.githubLogin
      ) {
        issues.push(
          `GitHub identity ${desired.githubLogin} is already linked to Google user ${user.id}`,
        );
      }
    }
  }
  if (issues.length > 0) throw new GitHubIdentityAdminAttestationError(issues);
}

function resolveGoogleSubject(
  attestation: z.output<typeof GitHubIdentityAdminAttestationSchema>,
  users: ReturnType<typeof parseDirectoryUsers>,
) {
  const matches = users.filter((candidate) =>
    attestation.subject.kind === "google-user-id"
      ? candidate.id === attestation.subject.googleUserId
      : candidate.primaryEmail.toLowerCase() ===
        attestation.subject.primaryEmail,
  );
  if (matches.length !== 1) {
    throw new GitHubIdentityAdminAttestationError([
      `Google subject for ${attestation.githubLogin} resolved to ${String(matches.length)} users`,
    ]);
  }
  const [user] = matches;
  if (user === undefined)
    throw new Error("unreachable Google identity resolution state");
  return user;
}

function readObservedIdentity(
  user: ReturnType<typeof parseDirectoryUsers>[number],
): ReadObservedIdentityResult {
  const schema = user.customSchemas?.SarjIdentity;
  const githubLogin = schema?.githubLogin;
  const githubUserId = schema?.githubUserId;
  if (githubLogin === undefined && githubUserId === undefined)
    return { kind: "unlinked" };
  const parsed = GoogleGithubIdentitySchema.safeParse({
    githubLogin,
    githubUserId,
  });
  return parsed.success
    ? { identity: parsed.data, kind: "linked" }
    : { kind: "invalid" };
}

function compatibleWithReviewedPlan(
  reviewed: Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>,
  current: Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>,
): boolean {
  if (dequal(reviewed, current)) return true;
  if (reviewed.kind !== "update" || current.kind !== "unchanged") return false;
  return sameIdentity(reviewed.desired, current.identity);
}

function sameIdentity(
  left: z.output<typeof GoogleGithubIdentitySchema>,
  right: z.output<typeof GoogleGithubIdentitySchema>,
): boolean {
  return (
    left.githubLogin === right.githubLogin &&
    left.githubUserId === right.githubUserId
  );
}

function duplicateValues(values: readonly string[], label: string): string[] {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts]
    .filter(([, count]) => count > 1)
    .map(([value]) => `duplicate ${label}: ${value}`);
}
