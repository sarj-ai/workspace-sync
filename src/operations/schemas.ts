import { z } from "zod";

import {
  ProviderReadinessContextSchema,
  validateProviderReadinessDiagnosticContext,
} from "../provider-readiness.ts";

const OperationRiskSchema = z.enum(["low", "medium", "high"]);

export const JsonValueSchema = z.json();
export type JsonValue = z.output<typeof JsonValueSchema>;

export const OperationActorSchema = z.strictObject({
  authorizationScope: z.string().trim().min(1).max(200),
  id: z.string().trim().min(1).max(200),
});
export type OperationActor = z.output<typeof OperationActorSchema>;

export const OperationHttpErrorSchema = z.strictObject({
  error: z.string().regex(/^[a-z][a-z0-9_]*$/),
  message: z.string().min(1).max(500),
});

export const OperationIdentifierSchema = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/);
const OperationConfirmationKeySchema = z
  .string()
  .regex(/^[a-z][a-zA-Z0-9]*(?:[._:-][a-zA-Z0-9]+)*$/);

export const OperationDiscoveryMetadataSchema = z.strictObject({
  destructive: z.boolean(),
  execution: z.enum(["sync", "workflow"]),
  requiredRole: z.string().regex(/^[a-z][a-z0-9:_-]{0,99}$/),
  requiredScope: z.string().regex(/^[a-z][a-z0-9:._-]{0,199}$/),
  risk: OperationRiskSchema,
  sourceSystems: z.array(OperationIdentifierSchema).min(1).max(20),
  summary: z.string().trim().min(1).max(200),
  supportsApply: z.boolean(),
  supportsPlan: z.literal(true),
  targetSystems: z.array(OperationIdentifierSchema).min(1).max(20),
});
export type OperationDiscoveryMetadata = z.output<
  typeof OperationDiscoveryMetadataSchema
>;

export const OperationDescriptorSchema =
  OperationDiscoveryMetadataSchema.extend({
    operationId: OperationIdentifierSchema,
  }).strict();
export type OperationDescriptor = z.output<typeof OperationDescriptorSchema>;

export const OperationDiscoveryResponseSchema = z.strictObject({
  operations: z.array(OperationDescriptorSchema),
});

export const OperationDiagnosticSchema = z
  .strictObject({
    actionId: OperationIdentifierSchema.optional(),
    code: z.string().trim().min(1).max(100),
    context: ProviderReadinessContextSchema.optional(),
    message: z.string().trim().min(1).max(2_000),
    severity: z.enum(["blocker", "warning", "info"]),
  })
  .superRefine(validateProviderReadinessDiagnosticContext);
export type OperationDiagnostic = z.output<typeof OperationDiagnosticSchema>;

export const SourceFingerprintSchema = z.strictObject({
  authority: z.string().trim().min(1).max(100),
  resourceId: z.string().trim().min(1).max(500),
  resourceType: z.string().trim().min(1).max(100),
  version: z.string().min(1).max(2_000),
});
export type SourceFingerprint = z.output<typeof SourceFingerprintSchema>;

export const OperationConfirmationCountsSchema = z.record(
  OperationConfirmationKeySchema,
  z.number().int().positive(),
);

const OperationConfirmationSchema = z.strictObject({
  allowed: z.boolean(),
  expectedCount: z.number().int().nonnegative(),
});

export const ManagedChangeSchema = z.strictObject({
  actionId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}$/),

  after: JsonValueSchema.nullable(),
  before: JsonValueSchema.nullable(),
  confirmationCounts: OperationConfirmationCountsSchema.optional(),
  details: JsonValueSchema,
  display: z.string().trim().min(1).max(2_000),
  kind: z.enum(["add", "change", "remove", "invoke"]),
  reason: z.string().trim().min(1).max(2_000),
  resource: z.strictObject({
    id: z.string().trim().min(1).max(500),
    type: z.string().trim().min(1).max(100),
  }),
  risk: OperationRiskSchema,
});
export type ManagedChange = z.output<typeof ManagedChangeSchema>;

export const PlanSummarySchema = z.strictObject({
  add: z.number().int().nonnegative(),
  change: z.number().int().nonnegative(),
  invoke: z.number().int().nonnegative(),
  remove: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
});
export type PlanSummary = z.output<typeof PlanSummarySchema>;

export const OperationPlanEnvelopeSchema = z.strictObject({
  actor: OperationActorSchema,
  applicable: z.boolean(),
  applyAuthorized: z.boolean(),
  changes: z.array(ManagedChangeSchema),
  diagnostics: z.array(OperationDiagnosticSchema),
  environment: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,99}$/),
  expiresAt: z.iso.datetime({ offset: true }),
  generatedAt: z.iso.datetime({ offset: true }),
  input: JsonValueSchema,
  operation: OperationIdentifierSchema,
  planHash: z.string().regex(/^[a-f0-9]{64}$/),
  policyVersion: z.string().trim().min(1).max(100),
  schemaVersion: z.literal(2),
  sourceFingerprints: z.array(SourceFingerprintSchema),
  summary: PlanSummarySchema,
});
export type OperationPlanEnvelope = z.output<
  typeof OperationPlanEnvelopeSchema
>;

export const SignedOperationPlanSchema = z.strictObject({
  plan: OperationPlanEnvelopeSchema,
  signature: z.string().regex(/^[a-f0-9]{64}$/),
});
export type SignedOperationPlan = z.output<typeof SignedOperationPlanSchema>;

export const ApplyOperationRequestSchema = z.strictObject({
  confirmPlanHash: z.string().regex(/^[a-f0-9]{64}$/),
  confirmations: z
    .record(OperationConfirmationKeySchema, OperationConfirmationSchema)
    .optional()
    .default({}),
  expectedActionIds: z
    .array(z.string().trim().min(1).max(200))
    .max(256)
    .refine(
      (ids) => new Set(ids).size === ids.length,
      "expected action ids must be unique",
    )
    .optional(),
  riskAcknowledged: z.boolean().optional().default(false),
  signedPlan: SignedOperationPlanSchema,
});
export type ApplyOperationRequest = z.output<
  typeof ApplyOperationRequestSchema
>;

export const ApplyActionResultSchema = z.strictObject({
  actionId: z.string().min(1),
  message: z.string().min(1).optional(),
  state: z.enum(["applied", "skipped", "failed"]),
});
export type ApplyActionResult = z.output<typeof ApplyActionResultSchema>;

const ApplyResultBaseShape = {
  actions: z.array(ApplyActionResultSchema),
  planHash: z.string().regex(/^[a-f0-9]{64}$/),
};

export const ApplyOperationResultSchema = z.discriminatedUnion("state", [
  z.strictObject({ ...ApplyResultBaseShape, state: z.literal("applied") }),
  z.strictObject({ ...ApplyResultBaseShape, state: z.literal("noop") }),
  z.strictObject({
    ...ApplyResultBaseShape,
    code: z.literal("plan_expired"),
    message: z.string().min(1),
    state: z.literal("expired"),
  }),
  z.strictObject({
    ...ApplyResultBaseShape,
    actionId: z.string().min(1).optional(),
    code: z.enum(["source_drift", "target_drift"]),
    message: z.string().min(1),
    state: z.literal("stale"),
  }),
  z.strictObject({
    ...ApplyResultBaseShape,
    code: z.enum([
      "mutation_confirmation_mismatch",
      "mutation_confirmation_required",
      "apply_not_supported",
      "plan_blocked",
      "risk_acknowledgement_required",
    ]),
    message: z.string().min(1),
    state: z.literal("blocked"),
  }),
  z.strictObject({
    ...ApplyResultBaseShape,
    code: z.enum([
      "read_failed",
      "write_failed",
      "readback_failed",
      "target_drift",
    ]),
    message: z.string().min(1),
    state: z.enum(["failed", "failed_partial"]),
  }),
]);
export type ApplyOperationResult = z.output<typeof ApplyOperationResultSchema>;
