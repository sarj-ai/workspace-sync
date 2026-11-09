import { dequal } from "dequal";
import { z } from "zod";

import {
  GitHubLoginSchema as CanonicalGitHubLoginSchema,
  GitHubUserIdSchema as CanonicalGitHubUserIdSchema,
  GoogleUserIdSchema,
} from "../catalog/identity-authority.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { assertGoogleIdentityParentAuthority } from "../identity-sync/assert-google-identity-parent-authority.ts";
import {
  GoogleIdentityMaintenanceFenceError,
  type GoogleIdentityMaintenanceWriteGuard,
} from "../identity-sync/google-identity-maintenance-fence-error.ts";
import type {
  GoogleIdentityParentContext,
  GoogleIdentityParentDispatch,
} from "../identity-sync/google-identity-parent-boundary-schema.ts";
import { GoogleIdentityParentBoundarySchema } from "../identity-sync/google-identity-parent-boundary-schema.ts";
import { GoogleIdentityParentPreflightError } from "../identity-sync/google-identity-parent-preflight-error.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { logEvent } from "../shared/log-event.ts";
import { defaultSleep, type Sleep } from "./http.ts";

const GithubIdentityFieldNameSchema = z.enum(["githubLogin", "githubUserId"]);

export const SARJ_IDENTITY_SCHEMA_NAME = "SarjIdentity";

export const GoogleSchemaFieldSchema = z.object({
  displayName: z.string().optional(),
  etag: z.string().min(1).optional(),
  fieldId: z.string().min(1).optional(),
  fieldName: z.string().min(1),
  fieldType: z.enum([
    "BOOL",
    "DATE",
    "DOUBLE",
    "EMAIL",
    "INT64",
    "PHONE",
    "STRING",
  ]),
  indexed: z.boolean().optional().default(true),
  kind: z.literal("admin#directory#schema#fieldspec").optional(),
  multiValued: z.boolean().optional().default(false),
  numericIndexingSpec: z
    .object({
      maxValue: z.number().optional(),
      minValue: z.number().optional(),
    })
    .optional(),
  readAccessType: z.string().min(1).optional(),
});

export const GoogleWorkspaceSchemaSnapshotSchema = z.object({
  displayName: z.string().min(1),
  etag: z.string().min(1),
  fields: z.array(GoogleSchemaFieldSchema),
  kind: z.literal("admin#directory#schema").optional(),
  schemaId: z.string().min(1),
  schemaName: z.string().min(1),
});

export const SarjIdentitySchemaFieldSchema = z.object({
  fieldName: GithubIdentityFieldNameSchema,
  fieldType: z.literal("STRING"),
  indexed: z.literal(true),
  multiValued: z.literal(false),
  readAccessType: z.literal("ADMINS_AND_SELF"),
});

export type SarjIdentitySchemaField = z.output<
  typeof SarjIdentitySchemaFieldSchema
>;
export type GoogleWorkspaceSchemaSnapshot = z.output<
  typeof GoogleWorkspaceSchemaSnapshotSchema
>;

const SarjIdentityObservedFieldSchema = z.strictObject({
  fieldName: GithubIdentityFieldNameSchema,
  fieldType: GoogleSchemaFieldSchema.shape.fieldType,
  indexed: z.boolean(),
  multiValued: z.boolean(),
  readAccessType: z.string().min(1).nullable(),
});

export const SarjIdentitySchemaManagedSliceSchema = z.strictObject({
  fields: z.array(SarjIdentityObservedFieldSchema),
  schemaName: z.string().min(1).nullable(),
});
export type SarjIdentitySchemaManagedSlice = z.output<
  typeof SarjIdentitySchemaManagedSliceSchema
>;

export const SARJ_IDENTITY_SCHEMA_FIELDS = [
  {
    fieldName: "githubLogin",
    fieldType: "STRING",
    indexed: true,
    multiValued: false,
    readAccessType: "ADMINS_AND_SELF",
  },
  {
    fieldName: "githubUserId",
    fieldType: "STRING",
    indexed: true,
    multiValued: false,
    readAccessType: "ADMINS_AND_SELF",
  },
] as const satisfies readonly SarjIdentitySchemaField[];

export interface GoogleWorkspaceIdentitySchemaGateway {
  addFields(
    snapshot: GoogleWorkspaceSchemaSnapshot,
    fields: readonly SarjIdentitySchemaField[],
  ): Promise<void>;
  createSchema(input: {
    displayName: typeof SARJ_IDENTITY_SCHEMA_NAME;
    fields: readonly SarjIdentitySchemaField[];
    schemaName: typeof SARJ_IDENTITY_SCHEMA_NAME;
  }): Promise<void>;
  readSchema(schemaName: typeof SARJ_IDENTITY_SCHEMA_NAME): Promise<unknown>;
}

const SARJ_IDENTITY_SCHEMA_PLAN_BASE = {
  after: SarjIdentitySchemaManagedSliceSchema,
  before: SarjIdentitySchemaManagedSliceSchema,
} as const;

export const SarjIdentitySchemaPlanSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...SARJ_IDENTITY_SCHEMA_PLAN_BASE,
    fields: z.array(SarjIdentitySchemaFieldSchema),
    kind: z.literal("add-fields"),
    schemaId: z.string().min(1),
  }),
  z.strictObject({
    ...SARJ_IDENTITY_SCHEMA_PLAN_BASE,
    issues: z.array(z.string().min(1)).min(1),
    kind: z.literal("blocked"),
  }),
  z.strictObject({
    ...SARJ_IDENTITY_SCHEMA_PLAN_BASE,
    fields: z.array(SarjIdentitySchemaFieldSchema),
    kind: z.literal("create"),
  }),
  z.strictObject({
    ...SARJ_IDENTITY_SCHEMA_PLAN_BASE,
    kind: z.literal("unchanged"),
    schemaId: z.string().min(1),
  }),
]);
export type SarjIdentitySchemaPlan = z.output<
  typeof SarjIdentitySchemaPlanSchema
>;
export type ExistingSarjIdentitySchemaPlan = Extract<
  SarjIdentitySchemaPlan,
  { kind: "add-fields" | "unchanged" }
>;
export const ReviewedSarjIdentitySchemaSliceSchema = z.strictObject({
  schemaId: z.string().min(1),
  managedSlice: SarjIdentitySchemaManagedSliceSchema,
});
export type ReviewedSarjIdentitySchemaSlice = z.output<
  typeof ReviewedSarjIdentitySchemaSliceSchema
>;

export type SarjIdentitySchemaReconciliation =
  | {
      mode: "apply";
      plan: Exclude<SarjIdentitySchemaPlan, { kind: "blocked" }>;
      verified: true;
    }
  | { mode: "dry-run"; plan: SarjIdentitySchemaPlan };

export class SarjIdentitySchemaCompatibilityError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[], options?: ErrorOptions) {
    super(`SarjIdentity schema is incompatible: ${issues.join(", ")}`, options);
    this.name = "SarjIdentitySchemaCompatibilityError";
    this.issues = issues;
  }
}

export interface ISarjIdentitySchemaService {
  applyPlan(
    plan: SarjIdentitySchemaPlan,
  ): Promise<SarjIdentitySchemaReconciliation>;
  plan(): Promise<SarjIdentitySchemaPlan>;
  readManagedSlice(): Promise<SarjIdentitySchemaManagedSlice>;
  readReviewedSchema?(
    plan: ExistingSarjIdentitySchemaPlan,
  ): Promise<ReviewedSarjIdentitySchemaSlice>;
  reconcile(
    mode: "apply" | "dry-run",
  ): Promise<SarjIdentitySchemaReconciliation>;
}

export class SarjIdentitySchemaService implements ISarjIdentitySchemaService {
  readonly #gateway: GoogleWorkspaceIdentitySchemaGateway;

  constructor(gateway: GoogleWorkspaceIdentitySchemaGateway) {
    this.#gateway = gateway;
  }

  async applyPlan(
    reviewed: SarjIdentitySchemaPlan,
  ): Promise<SarjIdentitySchemaReconciliation> {
    if (reviewed.kind === "blocked") {
      throw new SarjIdentitySchemaCompatibilityError(reviewed.issues);
    }
    const wire = await this.#gateway.readSchema(SARJ_IDENTITY_SCHEMA_NAME);
    if (reviewed.kind !== "create")
      assertReviewedSchemaId(wire, reviewed.schemaId);
    const current = managedSlice(wire);
    if (sameManagedSlice(current, reviewed.after)) {
      return { mode: "apply", plan: reviewed, verified: true };
    }
    if (!sameManagedSlice(current, reviewed.before)) {
      throw new SarjIdentitySchemaCompatibilityError([
        "managed schema drifted after PLAN",
      ]);
    }

    let mutationError: unknown;
    // A timed-out POST or PUT can commit remotely. Only an exact readback may convert that
    // ambiguous provider error into success.
    try {
      if (reviewed.kind === "create") {
        await this.#gateway.createSchema({
          displayName: SARJ_IDENTITY_SCHEMA_NAME,
          fields: reviewed.fields,
          schemaName: SARJ_IDENTITY_SCHEMA_NAME,
        });
      }
      if (reviewed.kind === "add-fields") {
        const snapshot = GoogleWorkspaceSchemaSnapshotSchema.parse(wire);
        if (snapshot.schemaId !== reviewed.schemaId) {
          throw new SarjIdentitySchemaCompatibilityError([
            "schema ID drifted after PLAN",
          ]);
        }
        await this.#gateway.addFields(snapshot, reviewed.fields);
      }
    } catch (error) {
      mutationError = error;
    }

    const reviewedSchema =
      reviewed.kind === "create"
        ? undefined
        : await this.readReviewedSchema(reviewed);
    const verification =
      reviewedSchema?.managedSlice ?? (await this.readManagedSlice());
    if (!sameManagedSlice(verification, reviewed.after)) {
      if (mutationError !== undefined) {
        throw new Error(
          "Google SarjIdentity schema mutation failed verification",
          {
            cause: mutationError,
          },
        );
      }
      throw new SarjIdentitySchemaCompatibilityError([
        "post-apply managed schema does not match",
      ]);
    }
    return { mode: "apply", plan: reviewed, verified: true };
  }

  async reconcile(
    mode: "apply" | "dry-run",
  ): Promise<SarjIdentitySchemaReconciliation> {
    const plan = await this.plan();
    if (mode === "dry-run") return { mode, plan };
    return this.applyPlan(plan);
  }

  async plan(): Promise<SarjIdentitySchemaPlan> {
    const wire = await this.#gateway.readSchema(SARJ_IDENTITY_SCHEMA_NAME);
    const before = managedSlice(wire);
    const after = desiredManagedSlice();
    if (wire === null) {
      return {
        after,
        before,
        fields: [...SARJ_IDENTITY_SCHEMA_FIELDS],
        kind: "create",
      };
    }
    const snapshot = GoogleWorkspaceSchemaSnapshotSchema.parse(wire);
    const issues: string[] = [];
    if (snapshot.schemaName !== SARJ_IDENTITY_SCHEMA_NAME) {
      issues.push(`schemaName must be ${SARJ_IDENTITY_SCHEMA_NAME}`);
    }
    const missingFields: SarjIdentitySchemaField[] = [];
    for (const expected of SARJ_IDENTITY_SCHEMA_FIELDS) {
      const matches = snapshot.fields.filter(
        (field) => field.fieldName === expected.fieldName,
      );
      if (matches.length > 1) {
        issues.push(`${expected.fieldName} is duplicated`);
        continue;
      }
      const [current] = matches;
      if (!current) {
        missingFields.push(expected);
        continue;
      }
      const parsed = SarjIdentitySchemaFieldSchema.safeParse(current);
      if (!parsed.success)
        issues.push(`${expected.fieldName} has incompatible settings`);
    }
    if (issues.length > 0) return { after, before, issues, kind: "blocked" };
    if (missingFields.length > 0) {
      return {
        after,
        before,
        fields: missingFields,
        kind: "add-fields",
        schemaId: snapshot.schemaId,
      };
    }
    return { after, before, kind: "unchanged", schemaId: snapshot.schemaId };
  }

  async readManagedSlice(): Promise<SarjIdentitySchemaManagedSlice> {
    return managedSlice(
      await this.#gateway.readSchema(SARJ_IDENTITY_SCHEMA_NAME),
    );
  }

  async readReviewedSchema(
    reviewed: ExistingSarjIdentitySchemaPlan,
  ): Promise<ReviewedSarjIdentitySchemaSlice> {
    const wire = await this.#gateway.readSchema(SARJ_IDENTITY_SCHEMA_NAME);
    const snapshot = assertReviewedSchemaId(wire, reviewed.schemaId);
    return ReviewedSarjIdentitySchemaSliceSchema.parse({
      schemaId: snapshot.schemaId,
      managedSlice: managedSlice(snapshot),
    });
  }
}

function assertReviewedSchemaId(wire: unknown, expectedSchemaId: string) {
  const snapshot = GoogleWorkspaceSchemaSnapshotSchema.safeParse(wire);
  if (!snapshot.success || snapshot.data.schemaId !== expectedSchemaId) {
    throw new SarjIdentitySchemaCompatibilityError([
      "schema ID drifted after PLAN",
    ]);
  }
  return snapshot.data;
}

function desiredManagedSlice(): SarjIdentitySchemaManagedSlice {
  return SarjIdentitySchemaManagedSliceSchema.parse({
    fields: SARJ_IDENTITY_SCHEMA_FIELDS,
    schemaName: SARJ_IDENTITY_SCHEMA_NAME,
  });
}

function managedSlice(wire: unknown): SarjIdentitySchemaManagedSlice {
  if (wire === null) {
    return SarjIdentitySchemaManagedSliceSchema.parse({
      fields: [],
      schemaName: null,
    });
  }
  const snapshot = GoogleWorkspaceSchemaSnapshotSchema.parse(wire);
  const managedNames: ReadonlySet<string> = new Set(
    SARJ_IDENTITY_SCHEMA_FIELDS.map(({ fieldName }) => fieldName),
  );
  const fields = snapshot.fields
    .filter(({ fieldName }) => managedNames.has(fieldName))
    .map(({ fieldName, fieldType, indexed, multiValued, readAccessType }) => ({
      fieldName,
      fieldType,
      indexed,
      multiValued,
      readAccessType: readAccessType ?? null,
    }))
    .toSorted((left, right) => left.fieldName.localeCompare(right.fieldName));
  return SarjIdentitySchemaManagedSliceSchema.parse({
    fields,
    schemaName: snapshot.schemaName,
  });
}

function sameManagedSlice(
  left: SarjIdentitySchemaManagedSlice,
  right: SarjIdentitySchemaManagedSlice,
): boolean {
  return dequal(left, right);
}

export const GoogleImmutableUserIdSchema = GoogleUserIdSchema;
export const GitHubLoginSchema = CanonicalGitHubLoginSchema;
export const GitHubUserIdSchema = CanonicalGitHubUserIdSchema;

export const GoogleGithubIdentitySchema = z.strictObject({
  githubLogin: GitHubLoginSchema,
  githubUserId: GitHubUserIdSchema,
});

const GoogleGitHubIdentityObservedSchema = z.strictObject({
  githubLogin: GitHubLoginSchema.optional(),
  githubUserId: GitHubUserIdSchema.optional(),
});
const GoogleCustomSchemasSnapshotSchema = z.record(
  z.string().min(1),
  z.record(z.string().min(1), JsonValueSchema),
);

export const GoogleIdentityUserSnapshotSchema = z.strictObject({
  archived: z.boolean().optional().default(false),
  customSchemas: GoogleCustomSchemasSnapshotSchema.optional(),
  deletionTime: z.iso.datetime().optional(),
  etag: z.string().min(1),
  id: GoogleImmutableUserIdSchema,
  primaryEmail: z.email(),
  suspended: z.boolean().optional().default(false),
});

export type GoogleGithubIdentity = z.output<typeof GoogleGithubIdentitySchema>;
export type GoogleIdentityUserSnapshot = z.output<
  typeof GoogleIdentityUserSnapshotSchema
>;

export interface GoogleWorkspaceIdentityUserGateway {
  readUserById(
    userId: z.input<typeof GoogleImmutableUserIdSchema>,
    deadlineAtMs?: number,
  ): Promise<unknown>;
  updateUser(input: {
    expectedEtag: string;
    identity: GoogleGithubIdentity;
    preservedCustomSchemas: z.output<typeof GoogleCustomSchemasSnapshotSchema>;
    userId: z.output<typeof GoogleImmutableUserIdSchema>;
    parentDispatch?: GoogleIdentityParentDispatch;
    maintenanceGuard?: GoogleIdentityMaintenanceWriteGuard;
  }): Promise<void>;
}

const GoogleIdentityUserPreconditionSchema = z.strictObject({
  etag: z.string().min(1),
  id: GoogleImmutableUserIdSchema,
  primaryEmail: z.email(),
});

export const GoogleGitHubIdentityPlanSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("blocked"),
    reason: z.enum(["deleted", "inactive", "not-found"]),
    userId: GoogleImmutableUserIdSchema,
  }),
  z.strictObject({
    current: GoogleGitHubIdentityObservedSchema.nullable(),
    desired: GoogleGithubIdentitySchema,
    kind: z.literal("update"),
    user: GoogleIdentityUserPreconditionSchema,
  }),
  z.strictObject({
    identity: GoogleGithubIdentitySchema,
    kind: z.literal("unchanged"),
    user: GoogleIdentityUserPreconditionSchema,
  }),
]);
export type GoogleGithubIdentityPlan = z.output<
  typeof GoogleGitHubIdentityPlanSchema
>;

export type GoogleGithubIdentityReconciliation =
  | {
      mode: "apply";
      plan: Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>;
      verified: true;
    }
  | { mode: "dry-run"; plan: GoogleGithubIdentityPlan };

export interface IGoogleGithubIdentityService {
  applyPlan(
    plan: GoogleGithubIdentityPlan,
    identityBudget?: IdentityWriteBudget,
    parentContext?: GoogleIdentityParentContext<GoogleGithubIdentityPlan>,
  ): Promise<GoogleGithubIdentityReconciliation>;
  plan(input: {
    desired: z.input<typeof GoogleGithubIdentitySchema>;
    userId: z.input<typeof GoogleImmutableUserIdSchema>;
  }): Promise<GoogleGithubIdentityPlan>;
  planFromSnapshot(input: {
    desired: z.input<typeof GoogleGithubIdentitySchema>;
    user: unknown;
    userId: z.input<typeof GoogleImmutableUserIdSchema>;
  }): GoogleGithubIdentityPlan;
  reconcile(input: {
    desired: z.input<typeof GoogleGithubIdentitySchema>;
    mode: "apply" | "dry-run";
    userId: z.input<typeof GoogleImmutableUserIdSchema>;
  }): Promise<GoogleGithubIdentityReconciliation>;
}

const GoogleIdentityReadbackDelaysMs = [250, 500, 1_000, 2_000] as const;
export const GoogleGithubIdentityApplyMaxProviderReads =
  2 + GoogleIdentityReadbackDelaysMs.length;
export const GoogleGithubIdentityParentApplyMaxProviderReads =
  GoogleGithubIdentityApplyMaxProviderReads + 3;

interface GoogleGithubIdentityServiceOptions {
  readbackDelaysMs?: readonly number[];
  sleep?: Sleep;
}

export class GoogleGithubIdentityService implements IGoogleGithubIdentityService {
  readonly #gateway: GoogleWorkspaceIdentityUserGateway;
  readonly #readbackDelaysMs: readonly number[];
  readonly #sleep: Sleep;

  constructor(
    gateway: GoogleWorkspaceIdentityUserGateway,
    options: GoogleGithubIdentityServiceOptions = {},
  ) {
    this.#gateway = gateway;
    this.#readbackDelaysMs =
      options.readbackDelaysMs ?? GoogleIdentityReadbackDelaysMs;
    this.#sleep = options.sleep ?? defaultSleep;
  }

  async applyPlan(
    reviewedInput: GoogleGithubIdentityPlan,
    identityBudget?: IdentityWriteBudget,
    parentContext?: GoogleIdentityParentContext<GoogleGithubIdentityPlan>,
  ): Promise<GoogleGithubIdentityReconciliation> {
    const reviewed = GoogleGitHubIdentityPlanSchema.parse(reviewedInput);
    if (reviewed.kind === "blocked") {
      throw new Error(`Google identity update blocked: ${reviewed.reason}`);
    }
    const parentDispatch = await this.#prepareParentDispatch(
      reviewed,
      identityBudget,
      parentContext,
    );
    const desired =
      reviewed.kind === "update" ? reviewed.desired : reviewed.identity;
    const wire = await this.#gateway.readUserById(reviewed.user.id);
    const current = this.#activeUser(wire, reviewed.user.id);
    const observed = observedIdentity(current);
    if (sameIdentity(observed, desired)) {
      if (parentContext !== undefined)
        throw new Error("google_identity_parent_unclaimed_convergence");
      return { mode: "apply", plan: reviewed, verified: true };
    }
    if (
      reviewed.kind !== "update" ||
      current.etag !== reviewed.user.etag ||
      current.primaryEmail !== reviewed.user.primaryEmail ||
      !sameObservedIdentity(observed, reviewed.current)
    ) {
      throw new Error("Google identity managed state drifted after PLAN");
    }

    await reserveIdentityWriteBudget(
      parentContext?.identityBudget ?? identityBudget,
      reviewed.user.id,
    );
    await parentDispatch?.assertWriteAuthority();
    let mutationError: unknown;
    try {
      await this.#gateway.updateUser({
        expectedEtag: reviewed.user.etag,
        identity: desired,
        preservedCustomSchemas: current.customSchemas ?? {},
        userId: reviewed.user.id,
        ...(!(parentDispatch === undefined) && { parentDispatch }),
      });
    } catch (error) {
      if (isGoogleIdentityWritePreflightError(error)) throw error;
      mutationError = error;
    }
    try {
      await this.#verifyExactReadback(reviewed.user.id, desired, 0);
    } catch (readbackError) {
      throw exactReadbackFailure(mutationError, readbackError);
    }
    return { mode: "apply", plan: reviewed, verified: true };
  }

  async plan(input: {
    desired: z.input<typeof GoogleGithubIdentitySchema>;
    userId: z.input<typeof GoogleImmutableUserIdSchema>;
  }): Promise<GoogleGithubIdentityPlan> {
    const userId = GoogleImmutableUserIdSchema.parse(input.userId);
    const wire = await this.#gateway.readUserById(userId);
    return this.planFromSnapshot({
      desired: input.desired,
      user:
        wire === null
          ? null
          : GoogleIdentityUserSnapshotSchema.strip().parse(wire),
      userId,
    });
  }

  planFromSnapshot(input: {
    desired: z.input<typeof GoogleGithubIdentitySchema>;
    user: unknown;
    userId: z.input<typeof GoogleImmutableUserIdSchema>;
  }): GoogleGithubIdentityPlan {
    const userId = GoogleImmutableUserIdSchema.parse(input.userId);
    const desired = GoogleGithubIdentitySchema.parse(input.desired);
    if (input.user === null)
      return { kind: "blocked", reason: "not-found", userId };
    const user = GoogleIdentityUserSnapshotSchema.parse(input.user);
    if (user.id !== userId)
      throw new Error(
        "Google Directory returned a different immutable user ID",
      );
    if (user.deletionTime !== undefined)
      return { kind: "blocked", reason: "deleted", userId };
    if (user.archived || user.suspended)
      return { kind: "blocked", reason: "inactive", userId };
    const current = observedIdentity(user);
    const precondition = {
      etag: user.etag,
      id: user.id,
      primaryEmail: user.primaryEmail,
    };
    if (sameIdentity(current, desired)) {
      return { identity: desired, kind: "unchanged", user: precondition };
    }
    return { current, desired, kind: "update", user: precondition };
  }

  async reconcile(input: {
    desired: z.input<typeof GoogleGithubIdentitySchema>;
    mode: "apply" | "dry-run";
    userId: z.input<typeof GoogleImmutableUserIdSchema>;
  }): Promise<GoogleGithubIdentityReconciliation> {
    const plan = await this.plan(input);
    if (input.mode === "dry-run") return { mode: input.mode, plan };
    return this.applyPlan(plan);
  }

  async #prepareParentDispatch(
    reviewed: Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>,
    identityBudget: IdentityWriteBudget | undefined,
    context: GoogleIdentityParentContext<GoogleGithubIdentityPlan> | undefined,
  ): Promise<GoogleIdentityParentDispatch | undefined> {
    if (context === undefined) return undefined;
    GoogleIdentityParentBoundarySchema.parse(context);
    if (
      (identityBudget !== undefined &&
        identityBudget !== context.identityBudget) ||
      reviewed.kind !== "update"
    )
      throw new Error("google_identity_parent_context_required");
    await this.#assertParentAuthority(reviewed, context);
    return {
      assertFreshPlan: () => context.assertFreshPlan(),
      assertWriteAuthority: () =>
        this.#assertParentAuthority(reviewed, context),
    };
  }

  async #assertParentAuthority(
    reviewed: Exclude<GoogleGithubIdentityPlan, { kind: "blocked" }>,
    context: GoogleIdentityParentContext<GoogleGithubIdentityPlan>,
  ): Promise<void> {
    context.assertFreshPlan();
    await context.verifyPreannouncement(reviewed);
    await context.assertWriteAuthority(reviewed);
    const users = await context.captureGoogleAuthority();
    const wire = await this.#gateway.readUserById(reviewed.user.id);
    await assertGoogleIdentityParentAuthority({
      expectedBeforeFingerprint: context.expectedBeforeFingerprint,
      googleUserId: reviewed.user.id,
      users,
      wire,
    });
    const current = this.#activeUser(wire, reviewed.user.id);
    if (
      reviewed.kind !== "update" ||
      current.etag !== reviewed.user.etag ||
      current.primaryEmail !== reviewed.user.primaryEmail ||
      !sameObservedIdentity(observedIdentity(current), reviewed.current)
    )
      throw new Error("google_identity_parent_reviewed_target_drift");
    context.assertFreshPlan();
  }

  #activeUser(wire: unknown, expectedId: string): GoogleIdentityUserSnapshot {
    if (wire === null)
      throw new Error("Google identity user disappeared after PLAN");
    const user = GoogleIdentityUserSnapshotSchema.strip().parse(wire);
    if (user.id !== expectedId)
      throw new Error(
        "Google Directory returned a different immutable user ID",
      );
    if (user.deletionTime !== undefined || user.archived || user.suspended) {
      throw new Error("Google identity user became inactive after PLAN");
    }
    return user;
  }

  async #verifyExactReadback(
    userId: string,
    desired: GoogleGithubIdentity,
    attempt = 0,
  ): Promise<void> {
    let readbackError: unknown;
    try {
      const verification = this.#activeUser(
        await this.#gateway.readUserById(userId),
        userId,
      );
      if (sameIdentity(observedIdentity(verification), desired)) return;
      readbackError = new Error(
        "Google identity update verification did not match the reviewed target",
      );
    } catch (error) {
      readbackError = error;
    }
    const delayMs = this.#readbackDelaysMs[attempt];
    if (delayMs === undefined) {
      logEvent("org_sync.google_github_identity_readback_exhausted", {
        attempts: attempt + 1,
      });
      throw readbackError;
    }
    logEvent("org_sync.google_github_identity_readback_retry", {
      attempt: attempt + 1,
      "delay_ms": delayMs,
    });
    await this.#sleep(delayMs);
    await this.#verifyExactReadback(userId, desired, attempt + 1);
  }
}

function observedIdentity(user: GoogleIdentityUserSnapshot) {
  const wire = user.customSchemas?.SarjIdentity;
  if (wire === undefined) return null;
  const parsed = GoogleGitHubIdentityObservedSchema.parse({
    ...(!(wire.githubLogin === undefined) && {
      githubLogin: wire.githubLogin,
    }),
    ...(!(wire.githubUserId === undefined) && {
      githubUserId: wire.githubUserId,
    }),
  });
  return Object.keys(parsed).length === 0 ? null : parsed;
}

function sameIdentity(
  current: null | z.output<typeof GoogleGitHubIdentityObservedSchema>,
  desired: GoogleGithubIdentity,
): boolean {
  return (
    current?.githubLogin === desired.githubLogin &&
    current.githubUserId === desired.githubUserId
  );
}

function sameObservedIdentity(
  left: null | z.output<typeof GoogleGitHubIdentityObservedSchema>,
  right: null | z.output<typeof GoogleGitHubIdentityObservedSchema>,
): boolean {
  return dequal(left, right);
}

function exactReadbackFailure(
  mutationError: unknown,
  readbackError: unknown,
): AggregateError {
  return new AggregateError(
    mutationError === undefined
      ? [readbackError]
      : [mutationError, readbackError],
    "Google identity update failed exact readback verification",
    { cause: readbackError },
  );
}

function isGoogleIdentityWritePreflightError(error: unknown): boolean {
  return (
    error instanceof GoogleIdentityParentPreflightError ||
    error instanceof GoogleIdentityMaintenanceFenceError
  );
}
