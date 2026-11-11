import { z } from "zod";

import type { PreparedOperationApply } from "./kernel.ts";

const PreflightCodeSchema = z.enum([
  "source_drift",
  "target_drift",
  "plan_expired",
  "plan_blocked",
  "read_failed",
  "mutation_confirmation_required",
  "mutation_confirmation_mismatch",
  "risk_acknowledgement_required",
  "apply_not_supported",
  "invalid_plan",
  "invalid_confirmation",
  "actor_mismatch",
  "environment_mismatch",
  "invalid_signature",
  "unknown",
]);

const PreflightStatusSchema = z.enum(["ready", "rejected"]);
const PreflightStateSchema = z.enum([
  "ready",
  "expired",
  "stale",
  "blocked",
  "failed",
  "failed_partial",
  "noop",
  "applied",
]);

export const PreflightDiagnosticSchema = z.strictObject({
  diagnosticOnly: z.literal(true),
  providerWrites: z.literal(0),
  planHash: z.string().regex(/^[a-f0-9]{64}$/),
  status: PreflightStatusSchema,
  state: PreflightStateSchema,
  code: PreflightCodeSchema.nullable(),
  pendingCount: z.number().int().nonnegative(),
  skippedCount: z.number().int().nonnegative(),
});

/* Ephemeral read evidence, never a reusable APPLY authorization. */
export function preflightDiagnostic(prepared: PreparedOperationApply) {
  const code = prepared.ok
    ? null
    : safePreflightCode(
        "code" in prepared.result ? prepared.result.code : undefined,
      );
  return PreflightDiagnosticSchema.parse({
    diagnosticOnly: true,
    providerWrites: 0,
    planHash: prepared.ok ? prepared.plan.planHash : prepared.result.planHash,
    status: prepared.ok ? "ready" : "rejected",
    state: prepared.ok ? "ready" : prepared.result.state,
    code,
    pendingCount: prepared.ok ? prepared.pending.length : 0,
    skippedCount: (prepared.ok
      ? prepared.actions
      : prepared.result.actions
    ).filter((action) => action.state === "skipped").length,
  });
}

export function safePreflightCode(code: unknown) {
  const parsed = PreflightCodeSchema.safeParse(code);
  return parsed.success ? parsed.data : "unknown";
}
