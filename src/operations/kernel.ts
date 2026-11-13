import { sameStringMultiset } from "../shared/same-string-multiset.ts";
import {
  bytesToHex,
  canonicalJson,
  hexToBytes,
  sameJson,
  sha256Hex,
} from "./canonical.ts";
import {
  type OperationRegistry,
  type OperationContext,
  OperationContractError,
  OperationSourceError,
  type RegisteredApplyOperation,
  type RegisteredOperation,
} from "./registry.ts";
import {
  type ApplyActionResult,
  type ApplyOperationRequest,
  ApplyOperationRequestSchema,
  type ApplyOperationResult,
  ApplyOperationResultSchema,
  type JsonValue,
  JsonValueSchema,
  type ManagedChange,
  type OperationActor,
  OperationActorSchema,
  type OperationPlanEnvelope,
  OperationPlanEnvelopeSchema,
  type PlanSummary,
  type SignedOperationPlan,
  SignedOperationPlanSchema,
  SourceFingerprintSchema,
} from "./schemas.ts";

const ENCODER = new TextEncoder();
const HMAC_ALGORITHM = { hash: "SHA-256", name: "HMAC" } as const;

export type OperationPlanErrorCode =
  | "actor_mismatch"
  | "environment_mismatch"
  | "invalid_confirmation"
  | "invalid_plan"
  | "invalid_signature"
  | "unknown_operation";

export class OperationPlanError extends Error {
  readonly code: OperationPlanErrorCode;

  constructor(
    options: ErrorOptions & { code: OperationPlanErrorCode; message: string },
  ) {
    super(options.message, options);
    this.name = "OperationPlanError";
    this.code = options.code;
  }
}

export interface OperationKernelOptions {
  now?: () => number;
  registry: OperationRegistry;
  signingKey: string;
}

export interface PlanOperationRequest {
  actor: OperationActor;
  environment: string;
  input: unknown;
  operation: string;
}

export interface ApplyOperationContext {
  actor: OperationActor;
  environment: string;
}

export interface OperationApplyPort {
  apply(
    rawRequest: unknown,
    rawContext: ApplyOperationContext,
  ): Promise<ApplyOperationResult>;
}

export interface OperationPlanPort {
  plan(request: PlanOperationRequest): Promise<SignedOperationPlan>;
}

export type PreparedOperationApply =
  | {
      actions: ApplyActionResult[];
      context: OperationContext;
      ok: true;
      operation: RegisteredApplyOperation;
      pending: ManagedChange[];
      plan: OperationPlanEnvelope;
    }
  | { ok: false; result: ApplyOperationResult };

export interface OperationPrepareApplyPort {
  prepareApply(
    rawRequest: unknown,
    rawContext: ApplyOperationContext,
  ): Promise<PreparedOperationApply>;
}

export class OperationKernel
  implements OperationApplyPort, OperationPlanPort, OperationPrepareApplyPort
{
  readonly #key: Promise<CryptoKey>;
  readonly #now: () => number;
  readonly #registry: OperationRegistry;

  constructor(options: OperationKernelOptions) {
    if (options.signingKey.length < 32) {
      throw new Error(
        "Operation plan signing key must be at least 32 characters",
      );
    }
    this.#registry = options.registry;
    this.#now = options.now ?? Date.now;
    this.#key = crypto.subtle.importKey(
      "raw",
      ENCODER.encode(options.signingKey),
      HMAC_ALGORITHM,
      false,
      ["sign", "verify"],
    );
  }

  async plan(request: PlanOperationRequest): Promise<SignedOperationPlan> {
    const actor = OperationActorSchema.parse(request.actor);
    const environment = parseEnvironment(request.environment);
    const operation = this.#requireOperation(request.operation);
    const nowMs = this.#now();
    const context = operationContext(actor, environment, nowMs);
    const { draft, input } = await operation.buildPlan(request.input, context);
    const normalized = await materializeOperationPlanStage(
      `${operation.name}.plan-normalization`,
      () => {
        assertUniqueChanges(draft.changes);
        assertDiagnosticActionIds(draft.diagnostics, operation.actionIds);
        return {
          applicable:
            draft.applicable &&
            draft.diagnostics.every(
              (diagnostic) =>
                diagnostic.severity !== "blocker" ||
                diagnostic.actionId !== undefined,
            ),
          diagnostics: draft.diagnostics,
          sourceFingerprints: normalizeFingerprints(draft.sourceFingerprints),
        };
      },
    );
    const generatedAt = new Date(nowMs).toISOString();
    const expiresAt = new Date(
      nowMs + operation.ttlSeconds * 1_000,
    ).toISOString();
    const semanticValue = await materializeOperationPlanStage(
      `${operation.name}.plan-semantic-value`,
      () =>
        JsonValueSchema.parse({
          actor,
          applicable: normalized.applicable,
          applyAuthorized: operation.metadata.supportsApply,
          changes: draft.changes.map(hashableChange),
          diagnostics: normalized.diagnostics,
          environment,
          input,
          operation: operation.name,
          policyVersion: operation.policyVersion,
          schemaVersion: 2,
          sourceFingerprints: normalized.sourceFingerprints,
        }),
    );
    const plan = await materializeOperationPlanStage(
      `${operation.name}.plan-envelope`,
      async () =>
        OperationPlanEnvelopeSchema.parse({
          actor,
          applicable: normalized.applicable,
          applyAuthorized: operation.metadata.supportsApply,
          changes: draft.changes,
          diagnostics: normalized.diagnostics,
          environment,
          expiresAt,
          generatedAt,
          input,
          operation: operation.name,
          planHash: await sha256Hex(semanticValue),
          policyVersion: operation.policyVersion,
          schemaVersion: 2,
          sourceFingerprints: normalized.sourceFingerprints,
          summary: summarize(draft.changes),
        }),
    );
    return materializeOperationPlanStage(
      `${operation.name}.plan-signature`,
      async () =>
        SignedOperationPlanSchema.parse({
          plan,
          signature: await this.#sign(plan),
        }),
    );
  }

  async apply(
    rawRequest: unknown,
    rawContext: ApplyOperationContext,
  ): Promise<ApplyOperationResult> {
    const prepared = await this.prepareApply(rawRequest, rawContext);
    if (!prepared.ok) return prepared.result;
    return this.#applyPending(
      prepared.operation,
      prepared.plan,
      prepared.context,
      prepared.pending,
      prepared.actions,
    );
  }

  /*
   * Verifies an APPLY request and re-reads every authoritative source and managed target without
   * mutating. Workflow launchers use this as their final compare-before-enqueue fence.
   */
  async prepareApply(
    rawRequest: unknown,
    rawContext: ApplyOperationContext,
  ): Promise<PreparedOperationApply> {
    const request = parseApplyRequest(rawRequest);
    const actor = OperationActorSchema.parse(rawContext.actor);
    const environment = parseEnvironment(rawContext.environment);
    await this.#verify(request.signedPlan);
    const { plan } = request.signedPlan;
    if ((await sha256Hex(semanticPlan(plan))) !== plan.planHash) {
      throw new OperationPlanError({
        code: "invalid_plan",
        message: "Plan hash does not match its semantic content",
      });
    }
    if (request.confirmPlanHash !== plan.planHash) {
      throw new OperationPlanError({
        code: "invalid_confirmation",
        message: "Plan hash confirmation does not match",
      });
    }
    if (!sameActor(plan.actor, actor)) {
      throw new OperationPlanError({
        code: "actor_mismatch",
        message: "Plan was issued to a different actor",
      });
    }
    if (plan.environment !== environment) {
      throw new OperationPlanError({
        code: "environment_mismatch",
        message: "Plan was issued for a different environment",
      });
    }
    const operation = this.#requireOperation(plan.operation);
    const nowMs = this.#now();
    const stabilityFailure = validatePlanStability(operation, plan, nowMs);
    if (stabilityFailure) return stabilityFailure;
    const capability = authorizeApplyCapability(operation, plan);
    if (!capability.ok) return capability;
    const applyOperation = capability.operation;
    if (!plan.applicable) {
      return {
        ok: false,
        result: result({
          actions: [],
          code: "plan_blocked",
          message: "Plan contains blocking diagnostics",
          planHash: plan.planHash,
          state: "blocked",
        }),
      };
    }
    const blockedActionIds = new Set(
      plan.diagnostics.flatMap((diagnostic) =>
        diagnostic.severity === "blocker" && diagnostic.actionId !== undefined
          ? [diagnostic.actionId]
          : [],
      ),
    );
    const actionableChanges = plan.changes.filter(
      (change) => !blockedActionIds.has(change.actionId),
    );
    const blockedActions: ApplyActionResult[] = plan.changes.flatMap((change) =>
      blockedActionIds.has(change.actionId)
        ? {
            actionId: change.actionId,
            message:
              "Skipped because the signed plan contains an action-scoped blocker",
            state: "skipped" as const,
          }
        : [],
    );
    const confirmationFailure = confirmMutationCounts(
      plan,
      request,
      actionableChanges,
    );
    if (confirmationFailure) return { ok: false, result: confirmationFailure };
    if (
      requiresRiskAcknowledgement(actionableChanges) &&
      !request.riskAcknowledged
    ) {
      return {
        ok: false,
        result: result({
          actions: [],
          code: "risk_acknowledgement_required",
          message:
            "High-risk and removal plans require explicit acknowledgement",
          planHash: plan.planHash,
          state: "blocked",
        }),
      };
    }

    const context = operationContext(actor, environment, nowMs);
    let freshSources: ReturnType<typeof normalizeFingerprints>;
    try {
      freshSources = normalizeFingerprints(
        await applyOperation.readSourceFingerprints(plan.input, context),
      );
    } catch (error) {
      return {
        ok: false,
        result: result({
          actions: [],
          code: "read_failed",
          message: error instanceof Error ? error.message : String(error),
          planHash: plan.planHash,
          state: "failed",
        }),
      };
    }
    if (
      !sameJson(
        JsonValueSchema.parse(plan.sourceFingerprints),
        JsonValueSchema.parse(freshSources),
      )
    ) {
      return {
        ok: false,
        result: result({
          actions: [],
          code: "source_drift",
          message: "An authoritative source changed after planning",
          planHash: plan.planHash,
          state: "stale",
        }),
      };
    }

    const preflight = await this.#preflight(
      applyOperation,
      plan,
      context,
      actionableChanges,
      blockedActions,
    );
    if (!preflight.ok) return preflight;
    assertExpectedActionIds(request.expectedActionIds, preflight.pending);
    return {
      actions: preflight.actions,
      context,
      ok: true,
      operation: applyOperation,
      pending: preflight.pending,
      plan,
    };
  }

  async #applyPending(
    operation: RegisteredApplyOperation,
    plan: OperationPlanEnvelope,
    context: OperationContext,
    pending: ManagedChange[],
    initialActions: ApplyActionResult[],
  ): Promise<ApplyOperationResult> {
    const actions = [...initialActions];
    let applied = 0;
    const applyNext = async (index: number): Promise<ApplyOperationResult> => {
      const change = pending[index];
      if (!change) {
        return result({
          actions,
          planHash: plan.planHash,
          state: applied === 0 ? "noop" : "applied",
        });
      }
      const currentResult = await readManagedSlice(operation, change, context);
      if (!currentResult.ok)
        return failedResult(
          plan.planHash,
          actions,
          applied,
          change.actionId,
          "read_failed",
          currentResult.error,
        );
      const current = currentResult.value;
      if (sameSlice(current, change.after)) {
        actions.push({ actionId: change.actionId, state: "skipped" });
        return applyNext(index + 1);
      }
      if (!sameSlice(current, change.before))
        return targetDriftResult(
          plan.planHash,
          actions,
          applied,
          change.actionId,
        );
      const writeResult = await applyAndVerifyChange(
        operation,
        change,
        context,
      );
      if (!writeResult.ok) {
        return failedResult(
          plan.planHash,
          actions,
          applied,
          change.actionId,
          writeResult.code,
          writeResult.error,
        );
      }
      actions.push({ actionId: change.actionId, state: "applied" });
      applied++;
      return applyNext(index + 1);
    };
    return applyNext(0);
  }

  async #preflight(
    operation: RegisteredApplyOperation,
    plan: OperationPlanEnvelope,
    context: OperationContext,
    changes: readonly ManagedChange[],
    initialActions: readonly ApplyActionResult[] = [],
  ): Promise<
    | { actions: ApplyActionResult[]; ok: true; pending: ManagedChange[] }
    | { ok: false; result: ApplyOperationResult }
  > {
    const actions: ApplyActionResult[] = [...initialActions];
    const pending: ManagedChange[] = [];
    const inspectNext = async (
      index: number,
    ): Promise<
      | { actions: ApplyActionResult[]; ok: true; pending: ManagedChange[] }
      | { ok: false; result: ApplyOperationResult }
    > => {
      const change = changes[index];
      if (!change) return { actions, ok: true, pending };
      let current: JsonValue | null;
      try {
        current = await operation.readManagedSlice(change, context);
      } catch (error) {
        return {
          ok: false,
          result: failedResult(
            plan.planHash,
            actions,
            0,
            change.actionId,
            "read_failed",
            error,
          ),
        };
      }
      if (sameSlice(current, change.after)) {
        actions.push({ actionId: change.actionId, state: "skipped" });
      } else if (sameSlice(current, change.before)) {
        pending.push(change);
      } else {
        return {
          ok: false,
          result: result({
            actionId: change.actionId,
            actions,
            code: "target_drift",
            message: `Managed target drifted for action ${change.actionId}`,
            planHash: plan.planHash,
            state: "stale",
          }),
        };
      }
      return inspectNext(index + 1);
    };
    return inspectNext(0);
  }

  #requireOperation(name: string): RegisteredOperation {
    const operation = this.#registry.get(name);
    if (!operation) {
      throw new OperationPlanError({
        code: "unknown_operation",
        message: `Unknown operation ${name}`,
      });
    }
    return operation;
  }

  async #sign(plan: OperationPlanEnvelope): Promise<string> {
    const signature = await crypto.subtle.sign(
      "HMAC",
      await this.#key,
      ENCODER.encode(canonicalJson(JsonValueSchema.parse(plan))),
    );
    return bytesToHex(new Uint8Array(signature));
  }

  async #verify(signedPlan: SignedOperationPlan): Promise<void> {
    const signature = hexToBytes(signedPlan.signature);
    if (!signature)
      throw new OperationPlanError({
        code: "invalid_signature",
        message: "Invalid plan signature",
      });
    const valid = await crypto.subtle.verify(
      "HMAC",
      await this.#key,
      signature,
      ENCODER.encode(canonicalJson(JsonValueSchema.parse(signedPlan.plan))),
    );
    if (!valid)
      throw new OperationPlanError({
        code: "invalid_signature",
        message: "Invalid plan signature",
      });
  }
}

async function materializeOperationPlanStage<Result>(
  component: string,
  build: () => Promise<Result> | Result,
): Promise<Result> {
  try {
    return await build();
  } catch (error) {
    if (
      error instanceof OperationContractError ||
      error instanceof OperationPlanError ||
      error instanceof OperationSourceError
    )
      throw error;
    throw new OperationContractError(component, { cause: error });
  }
}

function assertExpectedActionIds(
  expectedActionIds: readonly string[] | undefined,
  pending: readonly ManagedChange[],
): void {
  if (
    expectedActionIds !== undefined &&
    !sameStringMultiset(
      expectedActionIds,
      pending.map(({ actionId }) => actionId),
    )
  ) {
    throw new OperationPlanError({
      code: "invalid_confirmation",
      message:
        "Expected action IDs do not match the exact preflight mutation set",
    });
  }
}

async function readManagedSlice(
  operation: RegisteredApplyOperation,
  change: ManagedChange,
  context: OperationContext,
): Promise<
  { error: unknown; ok: false } | { ok: true; value: JsonValue | null }
> {
  try {
    return {
      ok: true,
      value: await operation.readManagedSlice(change, context),
    };
  } catch (error) {
    return { error, ok: false };
  }
}

function targetDriftResult(
  planHash: string,
  actions: ApplyActionResult[],
  applied: number,
  actionId: string,
): ApplyOperationResult {
  if (!hasCompletedAction(actions, applied)) {
    return result({
      actionId,
      actions,
      code: "target_drift",
      message: "A managed target changed immediately before its write",
      planHash,
      state: "stale",
    });
  }
  return result({
    actions,
    code: "target_drift",
    message: `Target drift stopped apply at action ${actionId}`,
    planHash,
    state: "failed_partial",
  });
}

async function applyAndVerifyChange(
  operation: RegisteredApplyOperation,
  change: ManagedChange,
  context: OperationContext,
): Promise<
  | { code: "readback_failed" | "write_failed"; error: unknown; ok: false }
  | { ok: true }
> {
  try {
    await operation.applyChange(change, context);
  } catch (error) {
    return { code: "write_failed", error, ok: false };
  }
  const observed = await readManagedSlice(operation, change, context);
  if (!observed.ok)
    return { code: "readback_failed", error: observed.error, ok: false };
  if (sameSlice(observed.value, change.after)) return { ok: true };
  return {
    code: "readback_failed",
    error: new Error(
      "Authoritative readback did not match the planned after-state",
    ),
    ok: false,
  };
}

function failedResult(
  planHash: string,
  actions: ApplyActionResult[],
  applied: number,
  actionId: string,
  code: "read_failed" | "readback_failed" | "write_failed",
  error: unknown,
): ApplyOperationResult {
  return result({
    actions: [
      ...actions,
      {
        actionId,
        message: error instanceof Error ? error.message : String(error),
        state: "failed" as const,
      },
    ],
    code,
    message: `Operation stopped at action ${actionId}`,
    planHash,
    state: hasCompletedAction(actions, applied) ? "failed_partial" : "failed",
  });
}

function assertUniqueChanges(changes: readonly ManagedChange[]): void {
  const actionIds = new Set<string>();
  const resources = new Set<string>();
  for (const change of changes) {
    const resource = `${change.resource.type}:${change.resource.id}`;
    if (actionIds.has(change.actionId)) {
      throw new OperationPlanError({
        code: "invalid_plan",
        message: `Operation planner emitted duplicate action id ${change.actionId}`,
      });
    }
    if (resources.has(resource)) {
      throw new OperationPlanError({
        code: "invalid_plan",
        message: `Operation planner emitted overlapping managed resource ${resource}`,
      });
    }
    actionIds.add(change.actionId);
    resources.add(resource);
  }
}

function assertDiagnosticActionIds(
  diagnostics: readonly { actionId?: string | undefined }[],
  declaredActionIds: ReadonlySet<string>,
): void {
  for (const diagnostic of diagnostics) {
    if (
      diagnostic.actionId !== undefined &&
      !declaredActionIds.has(diagnostic.actionId)
    ) {
      throw new OperationPlanError({
        code: "invalid_plan",
        message: `Operation planner scoped a diagnostic to unknown action ${diagnostic.actionId}`,
      });
    }
  }
}

function hashableChange(change: ManagedChange): JsonValue {
  return JsonValueSchema.parse({
    actionId: change.actionId,
    after: change.after,
    before: change.before,
    ...(!(change.confirmationCounts === undefined) && {
      confirmationCounts: change.confirmationCounts,
    }),
    details: change.details,
    kind: change.kind,
    resource: change.resource,
    risk: change.risk,
  });
}

function hasCompletedAction(
  actions: readonly ApplyActionResult[],
  applied: number,
): boolean {
  return applied > 0 || actions.some((action) => action.state !== "failed");
}

function normalizeFingerprints(fingerprints: readonly unknown[]) {
  return fingerprints
    .map((fingerprint) => SourceFingerprintSchema.parse(fingerprint))
    .toSorted(
      (left, right) =>
        left.authority.localeCompare(right.authority) ||
        left.resourceType.localeCompare(right.resourceType) ||
        left.resourceId.localeCompare(right.resourceId) ||
        left.version.localeCompare(right.version),
    );
}

function operationContext(
  actor: OperationActor,
  environment: string,
  nowMs: number,
): OperationContext {
  return { actor, environment, now: new Date(nowMs) };
}

function parseApplyRequest(raw: unknown) {
  const parsed = ApplyOperationRequestSchema.safeParse(raw);
  if (!parsed.success) {
    throw new OperationPlanError({
      code: "invalid_plan",
      message: "Invalid apply request",
    });
  }
  return parsed.data;
}

function parseEnvironment(value: string): string {
  const parsed = OperationPlanEnvelopeSchema.shape.environment.safeParse(value);
  if (!parsed.success)
    throw new OperationPlanError({
      code: "invalid_plan",
      message: "Invalid environment",
    });
  return parsed.data;
}

function requiresRiskAcknowledgement(
  changes: readonly ManagedChange[],
): boolean {
  return changes.some(
    (change) => change.kind === "remove" || change.risk === "high",
  );
}

function semanticPlan(plan: OperationPlanEnvelope): JsonValue {
  return JsonValueSchema.parse({
    actor: plan.actor,
    applicable: plan.applicable,
    applyAuthorized: plan.applyAuthorized,
    changes: plan.changes.map(hashableChange),
    diagnostics: plan.diagnostics,
    environment: plan.environment,
    input: plan.input,
    operation: plan.operation,
    policyVersion: plan.policyVersion,
    schemaVersion: plan.schemaVersion,
    sourceFingerprints: plan.sourceFingerprints,
  });
}

function result(value: ApplyOperationResult): ApplyOperationResult {
  return ApplyOperationResultSchema.parse(value);
}

function authorizeApplyCapability(
  operation: RegisteredOperation,
  plan: OperationPlanEnvelope,
):
  | { ok: false; result: ApplyOperationResult }
  | { ok: true; operation: RegisteredApplyOperation } {
  if (plan.applyAuthorized && isApplyOperation(operation))
    return { ok: true, operation };
  return {
    ok: false,
    result: result({
      actions: [],
      code: "apply_not_supported",
      message:
        "The signed plan or current operation is PLAN-only and does not support APPLY",
      planHash: plan.planHash,
      state: "blocked",
    }),
  };
}

function isApplyOperation(
  operation: RegisteredOperation,
): operation is RegisteredApplyOperation {
  return operation.metadata.supportsApply;
}

function validatePlanStability(
  operation: RegisteredOperation,
  plan: OperationPlanEnvelope,
  nowMs: number,
): Extract<PreparedOperationApply, { ok: false }> | null {
  if (operation.policyVersion !== plan.policyVersion) {
    return {
      ok: false,
      result: result({
        actions: [],
        code: "source_drift",
        message: "Operation policy changed; create and review a new plan",
        planHash: plan.planHash,
        state: "stale",
      }),
    };
  }
  if (nowMs >= Date.parse(plan.expiresAt)) {
    return {
      ok: false,
      result: result({
        actions: [],
        code: "plan_expired",
        message: "Plan expired; create and review a new plan",
        planHash: plan.planHash,
        state: "expired",
      }),
    };
  }
  return null;
}

function sameActor(left: OperationActor, right: OperationActor): boolean {
  return (
    left.id === right.id &&
    sameJson(
      JsonValueSchema.parse(left.authorizationScope),
      JsonValueSchema.parse(right.authorizationScope),
    )
  );
}

function sameSlice(left: JsonValue | null, right: JsonValue | null): boolean {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}

function summarize(changes: readonly ManagedChange[]): PlanSummary {
  const summary: PlanSummary = {
    add: 0,
    change: 0,
    invoke: 0,
    remove: 0,
    total: changes.length,
  };
  for (const change of changes) summary[change.kind]++;
  return summary;
}

function confirmMutationCounts(
  plan: OperationPlanEnvelope,
  request: ApplyOperationRequest,
  changes: readonly ManagedChange[],
): ApplyOperationResult | null {
  const planned = new Map<string, number>();
  for (const change of changes) {
    if (change.confirmationCounts != null) {
      for (const [key, count] of Object.entries(change.confirmationCounts)) {
        planned.set(key, (planned.get(key) ?? 0) + count);
      }
    }
  }
  for (const [key, count] of [...planned].toSorted(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const confirmation = request.confirmations[key];
    if (confirmation?.allowed !== true) {
      return result({
        actions: [],
        code: "mutation_confirmation_required",
        message: `Mutation confirmation ${key} requires explicit operator approval`,
        planHash: plan.planHash,
        state: "blocked",
      });
    }
    if (confirmation.expectedCount !== count) {
      return result({
        actions: [],
        code: "mutation_confirmation_mismatch",
        message: `Mutation confirmation ${key} does not match the signed plan count`,
        planHash: plan.planHash,
        state: "blocked",
      });
    }
  }
  return null;
}
