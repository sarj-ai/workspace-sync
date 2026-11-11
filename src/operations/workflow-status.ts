import { z } from "zod";

export const WorkflowProviderStatusSchema = z.enum([
  "queued",
  "running",
  "paused",
  "errored",
  "terminated",
  "complete",
  "waiting",
  "waitingForPause",
  "rollingBack",
  "unknown",
]);
export type WorkflowProviderStatus = z.output<
  typeof WorkflowProviderStatusSchema
>;

const WORKFLOW_HASH_PATTERN = /^[a-f0-9]{64}$/u;
// zod-to-openapi 9.1 serializes regex flags; JSON Schema needs only the source.
const WorkflowHashSchema = z
  .string()
  .regex(WORKFLOW_HASH_PATTERN)
  .meta({ pattern: WORKFLOW_HASH_PATTERN.source });
const WorkflowRunBase = {
  instanceId: WorkflowHashSchema,
} as const;
const WorkflowUnitSchema = z.strictObject({
  id: z.string().trim().min(1).max(100),
  state: z.enum(["applied", "audited", "disabled", "skipped"]),
});
const WorkflowErrorSchema = z.strictObject({
  message: z.string().trim().min(1).max(500),
  name: z.string().trim().min(1).max(100),
});

export const OperationWorkflowStatusSchema = z.discriminatedUnion("state", [
  z.strictObject({
    ...WorkflowRunBase,
    providerStatus: z.enum(["queued", "running", "waiting", "rollingBack"]),
    state: z.literal("pending"),
  }),
  z.strictObject({
    ...WorkflowRunBase,
    providerStatus: z.enum(["paused", "waitingForPause"]),
    state: z.literal("paused"),
  }),
  z.strictObject({
    ...WorkflowRunBase,
    error: WorkflowErrorSchema.nullable(),
    providerStatus: z.enum(["errored", "terminated"]),
    state: z.literal("failed"),
  }),
  z.strictObject({
    ...WorkflowRunBase,
    planHash: WorkflowHashSchema,
    providerStatus: z.literal("complete"),
    state: z.literal("succeeded"),
    units: z.array(WorkflowUnitSchema).min(1),
  }),
  z.strictObject({
    ...WorkflowRunBase,
    providerStatus: z.literal("unknown"),
    state: z.literal("unknown"),
  }),
]);
export type OperationWorkflowStatus = z.output<
  typeof OperationWorkflowStatusSchema
>;

export class WorkflowRunConflictError extends Error {
  readonly code = "workflow_paused";
  readonly providerStatus: "paused" | "waitingForPause";

  constructor(
    providerStatus: "paused" | "waitingForPause",
    options?: ErrorOptions,
  ) {
    super(
      "The existing Workflow run is paused and cannot be safely restarted.",
      options,
    );
    this.name = "WorkflowRunConflictError";
    this.providerStatus = providerStatus;
  }
}
