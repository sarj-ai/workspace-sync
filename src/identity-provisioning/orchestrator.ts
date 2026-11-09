import { z } from "zod";

import {
  AuthorityIdentitySchema,
  type DesiredProvisioningPlan,
  type ProvisioningProviderId,
} from "../catalog/identity-authority.ts";
import { sha256 } from "../runtime/sha256.ts";
import { logEvent } from "../shared/log-event.ts";
import type {
  IdentityProviderConnector,
  IdentityProviderPlanningContext,
  IdentityProvisioningExecutionPolicy,
  IdentityProvisioningSha256,
  ProviderLifecycleAction,
  ProviderPlanningDecision,
} from "./contracts.ts";
import {
  IdentityProvisioningExecutionPolicySchema,
  identityProvisioningSha256,
  ProviderApplyReceiptSchema,
  ProviderLifecycleProtocolSchema,
  ProviderObservationSchema,
  ProviderVerificationSchema,
} from "./contracts.ts";
import { bootstrapEmployeeEntitlementAuthority } from "./employee-entitlement-policy.ts";
import type {
  IdentityReconciliationExecutionStore,
  IdentityReconciliationOperationClaim,
  IdentityReconciliationRunId,
} from "./persistence.ts";
import {
  IdentityReconciliationRunIdSchema,
  identityReconciliationOperationInput,
  identityReconciliationRunInput,
} from "./persistence.ts";
import { protectedIdentityBlocker } from "./protected-identity-blocker.ts";

type ExecutablePlan = Exclude<DesiredProvisioningPlan, { kind: "blocked" }>;
const ProvisioningConcurrencySchema = z.number().int().min(1).max(20);
const DEFAULT_PROVISIONING_CONCURRENCY = 5;

export type IdentityProvisioningExecutionResult =
  | {
      readonly errorCode: string;
      readonly googleUserId: string;
      readonly kind: "failed";
      readonly operationKey: string;
      readonly providerId: ProvisioningProviderId;
    }
  | {
      readonly googleUserId: string;
      readonly kind: "audit-only" | "claim-unavailable";
      readonly operationKey: string;
      readonly providerId: ProvisioningProviderId;
    }
  | {
      readonly googleUserId: string;
      readonly kind: "provider-disabled";
      readonly operationKey: string;
      readonly providerId: ProvisioningProviderId;
      readonly reasonCode:
        | "approval_invalid"
        | "bounded_policy_rejected"
        | "connector_action_not_managed"
        | "kill_switch_engaged";
    }
  | {
      readonly googleUserId: string;
      readonly kind: "succeeded";
      readonly operationKey: string;
      readonly providerId: ProvisioningProviderId;
      readonly resultHash: IdentityProvisioningSha256;
    };

export type IdentityProvisioningPlanningResult =
  | {
      readonly decision: ProviderPlanningDecision;
      readonly googleUserId: string;
      readonly kind: "planned";
      readonly providerId: ProvisioningProviderId;
    }
  | {
      readonly errorCode: string;
      readonly googleUserId: string;
      readonly kind: "failed";
      readonly providerId: ProvisioningProviderId;
    };

export interface IdentityProvisioningRunResult {
  readonly executions: readonly IdentityProvisioningExecutionResult[];
  readonly planHash: IdentityProvisioningSha256 | null;
  readonly planning: readonly IdentityProvisioningPlanningResult[];
  readonly runId: IdentityReconciliationRunId;
}

export interface IdentityProvisioningOrchestratorDependencies {
  readonly captureEmployeeEntitlementAuthority?: () => Promise<
    IdentityProviderPlanningContext["employeeEntitlementAuthority"]
  >;
  readonly claimDurationMs: number;
  readonly claimOwnerId: () => string;
  readonly clock: () => number;
  readonly connectors: readonly IdentityProviderConnector[];
  readonly maxConcurrency?: number;
  readonly repository: IdentityReconciliationExecutionStore;
  readonly runId: () => string;
}

export interface IdentityProvisioningReconciler {
  reconcile(
    rawSubjects: readonly unknown[],
    policy: IdentityProvisioningExecutionPolicy,
  ): Promise<IdentityProvisioningRunResult>;
}

export class IdentityProvisioningOrchestrator implements IdentityProvisioningReconciler {
  readonly #connectors: ReadonlyMap<ProvisioningProviderId, ValidatedConnector>;
  readonly #dependencies: IdentityProvisioningOrchestratorDependencies;
  readonly #maxConcurrency: number;

  constructor(dependencies: IdentityProvisioningOrchestratorDependencies) {
    this.#dependencies = dependencies;
    this.#connectors = connectorMap(dependencies.connectors);
    this.#maxConcurrency = ProvisioningConcurrencySchema.parse(
      dependencies.maxConcurrency ?? DEFAULT_PROVISIONING_CONCURRENCY,
    );
  }

  async reconcile(
    rawSubjects: readonly unknown[],
    rawPolicy: IdentityProvisioningExecutionPolicy,
  ): Promise<IdentityProvisioningRunResult> {
    const policy = IdentityProvisioningExecutionPolicySchema.parse(rawPolicy);
    if (
      policy.kind === "bounded-automatic-deprovision" &&
      rawSubjects.length > policy.maxSubjects
    ) {
      throw new IdentityProvisioningSafetyPolicyError(
        "automatic_subject_cap_exceeded",
      );
    }
    const subjects = rawSubjects.map((subject) =>
      AuthorityIdentitySchema.parse(subject),
    );
    const runId = IdentityReconciliationRunIdSchema.parse(
      this.#dependencies.runId(),
    );
    const employeeEntitlementAuthority =
      await (this.#dependencies.captureEmployeeEntitlementAuthority?.() ??
        Promise.resolve(bootstrapEmployeeEntitlementAuthority()));
    const planning = await this.#plan(subjects, {
      employeeEntitlementAuthority,
    });
    const operations = planning.flatMap((result) =>
      result.kind === "planned" &&
      result.decision.kind !== "blocked" &&
      result.decision.kind !== "satisfied"
        ? [result.decision]
        : [],
    );
    if (operations.length === 0)
      return { executions: [], planHash: null, planning, runId };

    const orderedOperations = operations.toSorted(compareOperations);
    const planHash = await hashPlan(orderedOperations);
    const canonicalRunId = await this.#dependencies.repository.createPlan(
      identityReconciliationRunInput({
        authorityRevision: aggregateAuthorityRevision(orderedOperations),
        createdAtMs: this.#dependencies.clock(),
        planHash,
        runId,
      }),
      orderedOperations.map((operation) =>
        identityReconciliationOperationInput({
          action: operation.kind,
          desiredStateHash: desiredStateHash(operation),
          googleUserId: operation.subject.googleUserId,
          operationKey: operation.idempotencyKey,
          provider: operation.target.providerId,
        }),
      ),
    );

    const executions = await mapWithConcurrency(
      orderedOperations,
      this.#maxConcurrency,
      (operation) => this.#execute(operation, policy, planHash),
    );
    return { executions, planHash, planning, runId: canonicalRunId };
  }

  async #plan(
    subjects: readonly ReturnType<typeof AuthorityIdentitySchema.parse>[],
    context: IdentityProviderPlanningContext,
  ): Promise<IdentityProvisioningPlanningResult[]> {
    const inputs = subjects.flatMap((subject) =>
      this.#connectors
        .values()
        .map(({ connector }) => ({ connector, subject }))
        .toArray(),
    );
    return mapWithConcurrency(
      inputs,
      this.#maxConcurrency,
      async ({ connector, subject }) => {
        try {
          const observation = ProviderObservationSchema.parse(
            await connector.observe(subject),
          );
          if (observation.providerId !== connector.providerId) {
            throw new Error("provider_observation_mismatch");
          }
          const decision = await connector.plan(subject, observation, context);
          return {
            decision,
            googleUserId: subject.googleUserId,
            kind: "planned",
            providerId: connector.providerId,
          } satisfies IdentityProvisioningPlanningResult;
        } catch (error) {
          logEvent("identity_provisioning.provider_planning_failed", {
            error: error instanceof Error ? error.message : String(error),
            "google_user_id": subject.googleUserId,
            "provider_id": connector.providerId,
          });
          return {
            errorCode: "provider_planning_failed",
            googleUserId: subject.googleUserId,
            kind: "failed",
            providerId: connector.providerId,
          } satisfies IdentityProvisioningPlanningResult;
        }
      },
    );
  }

  async #execute(
    operation: ExecutablePlan,
    policy: IdentityProvisioningExecutionPolicy,
    planHash: IdentityProvisioningSha256,
  ): Promise<IdentityProvisioningExecutionResult> {
    const entry = this.#connectors.get(operation.target.providerId);
    const identity = executionIdentity(operation);
    if (!entry)
      return { ...identity, errorCode: "provider_missing", kind: "failed" };
    const { connector, protocol } = entry;
    if (connector.execution === "audit-only" || policy.kind === "audit-only") {
      return { ...identity, kind: "audit-only" };
    }
    const managedActions = new Set<ProviderLifecycleAction>(
      protocol.managedActions,
    );
    if (!managedActions.has(operation.kind)) {
      return providerDisabledExecution(
        operation,
        identity,
        "connector_action_not_managed",
      );
    }
    if (policy.kind === "kill-switch-engaged") {
      return providerDisabledExecution(
        operation,
        identity,
        "kill_switch_engaged",
      );
    }
    if (policy.kind === "bounded-automatic-deprovision") {
      if (
        operation.kind !== "deprovision" ||
        operation.target.providerId !== policy.enabledProviders[0]
      ) {
        return providerDisabledExecution(
          operation,
          identity,
          "bounded_policy_rejected",
        );
      }
      const claimed =
        await this.#dependencies.repository.claimAutomaticDeprovisionOperation(
          { operation, planHash, policy },
          this.#dependencies.claimOwnerId(),
          this.#dependencies.clock(),
          this.#dependencies.claimDurationMs,
        );
      if (claimed.kind === "unavailable")
        return { ...identity, kind: "claim-unavailable" };
      return this.#applyAndVerify(
        connector,
        operation,
        claimed.claim,
        identity,
      );
    }
    const nowMs = this.#dependencies.clock();
    if (
      policy.approval.planHash !== planHash ||
      policy.approval.approvedAtMs > nowMs ||
      policy.approval.expiresAtMs <= nowMs ||
      !policy.enabledProviders.includes(operation.target.providerId)
    ) {
      return providerDisabledExecution(operation, identity, "approval_invalid");
    }

    return this.#executeClaimed(connector, operation, identity);
  }

  async #executeClaimed(
    connector: Extract<IdentityProviderConnector, { execution: "managed" }>,
    operation: ExecutablePlan,
    identity: ReturnType<typeof executionIdentity>,
  ): Promise<IdentityProvisioningExecutionResult> {
    const claimed = await this.#dependencies.repository.claimOperation(
      operation.idempotencyKey,
      this.#dependencies.claimOwnerId(),
      this.#dependencies.clock(),
      this.#dependencies.claimDurationMs,
    );
    if (claimed.kind === "unavailable")
      return { ...identity, kind: "claim-unavailable" };
    return this.#applyAndVerify(connector, operation, claimed.claim, identity);
  }

  async #applyAndVerify(
    connector: Extract<IdentityProviderConnector, { execution: "managed" }>,
    operation: ExecutablePlan,
    claim: IdentityReconciliationOperationClaim,
    identity: ReturnType<typeof executionIdentity>,
  ): Promise<IdentityProvisioningExecutionResult> {
    try {
      if (protectedIdentityBlocker(operation.subject) !== undefined) {
        throw new IdentityProvisioningSafetyPolicyError(
          "protected_google_identity",
        );
      }
      const receipt = ProviderApplyReceiptSchema.parse(
        await connector.apply(operation),
      );
      if (receipt.idempotencyKey !== operation.idempotencyKey) {
        throw new Error("provider_receipt_idempotency_mismatch");
      }
      const verification = ProviderVerificationSchema.parse(
        await connector.verify(operation, receipt),
      );
      if (verification.kind === "mismatch") {
        await this.#dependencies.repository.retryOperation(
          claim,
          "provider_verification_failed",
        );
        return {
          ...identity,
          errorCode: verification.errorCode,
          kind: "failed",
        };
      }
      await this.#dependencies.repository.completeOperation(
        claim,
        verification.resultHash,
        this.#dependencies.clock(),
      );
      return {
        ...identity,
        kind: "succeeded",
        resultHash: verification.resultHash,
      };
    } catch (error) {
      await retryWithoutMasking(this.#dependencies.repository, claim);
      logEvent("identity_provisioning.provider_operation_failed", {
        error: error instanceof Error ? error.message : String(error),
        "google_user_id": operation.subject.googleUserId,
        "operation_key": operation.idempotencyKey,
        "provider_id": operation.target.providerId,
      });
      return {
        ...identity,
        errorCode: "provider_operation_failed",
        kind: "failed",
      };
    }
  }
}

export class IdentityProvisioningSafetyPolicyError extends Error {
  constructor(code: string, options?: ErrorOptions) {
    super(code, options);
    this.name = "IdentityProvisioningSafetyPolicyError";
  }
}

async function mapWithConcurrency<Input, Output>(
  inputs: readonly Input[],
  concurrency: number,
  transform: (input: Input) => Promise<Output>,
): Promise<Output[]> {
  const output: Output[] = [];
  for (let index = 0; index < inputs.length; index += concurrency) {
    // eslint-disable-next-line no-await-in-loop -- Sequential batches enforce the provider concurrency ceiling.
    const batch = await Promise.all(
      inputs.slice(index, index + concurrency).map(transform),
    );
    output.push(...batch);
  }
  return output;
}

function connectorMap(
  connectors: readonly IdentityProviderConnector[],
): ReadonlyMap<ProvisioningProviderId, ValidatedConnector> {
  const result = new Map<ProvisioningProviderId, ValidatedConnector>();
  for (const connector of connectors) {
    if (result.has(connector.providerId))
      throw new Error("duplicate_identity_provider_connector");
    const protocol = ProviderLifecycleProtocolSchema.parse(connector.protocol);
    if (protocol.providerId !== connector.providerId) {
      throw new Error("identity_provider_protocol_provider_mismatch");
    }
    if (protocol.execution !== connector.execution) {
      throw new Error("identity_provider_protocol_execution_mismatch");
    }
    result.set(connector.providerId, { connector, protocol });
  }
  return result;
}

interface ValidatedConnector {
  readonly connector: IdentityProviderConnector;
  readonly protocol: ReturnType<typeof ProviderLifecycleProtocolSchema.parse>;
}

type ProviderDisabledReasonCode = Extract<
  IdentityProvisioningExecutionResult,
  { kind: "provider-disabled" }
>["reasonCode"];

function providerDisabledExecution(
  operation: ExecutablePlan,
  identity: ReturnType<typeof executionIdentity>,
  reasonCode: ProviderDisabledReasonCode,
): Extract<IdentityProvisioningExecutionResult, { kind: "provider-disabled" }> {
  logEvent("identity_provisioning.provider_operation_disabled", {
    action: operation.kind,
    "operation_key": operation.idempotencyKey,
    "provider_id": operation.target.providerId,
    "reason_code": reasonCode,
  });
  return { ...identity, kind: "provider-disabled", reasonCode };
}

function executionIdentity(operation: ExecutablePlan) {
  return {
    googleUserId: operation.subject.googleUserId,
    operationKey: operation.idempotencyKey,
    providerId: operation.target.providerId,
  } as const;
}

function desiredStateHash(operation: ExecutablePlan): string {
  const digest = operation.idempotencyKey.split(":").at(-1);
  if (!digest) throw new Error("operation_key_missing_digest");
  return digest;
}

function compareOperations(
  left: ExecutablePlan,
  right: ExecutablePlan,
): number {
  return left.idempotencyKey.localeCompare(right.idempotencyKey);
}

function aggregateAuthorityRevision(
  operations: readonly ExecutablePlan[],
): string {
  return operations
    .map((operation) => operation.subject.authorityRevision)
    .toSorted()
    .join(",");
}

async function hashPlan(
  operations: readonly ExecutablePlan[],
): Promise<IdentityProvisioningSha256> {
  const canonical = JSON.stringify(
    operations.map((operation) => ({
      action: operation.kind,
      idempotencyKey: operation.idempotencyKey,
      providerId: operation.target.providerId,
      subjectId: operation.subject.googleUserId,
    })),
  );
  return identityProvisioningSha256(await sha256(canonical));
}

async function retryWithoutMasking(
  repository: IdentityReconciliationExecutionStore,
  claim: IdentityReconciliationOperationClaim,
): Promise<void> {
  try {
    await repository.retryOperation(claim, "provider_operation_failed");
  } catch (error) {
    logEvent("identity_provisioning.retry_record_failed", {
      error: error instanceof Error ? error.message : String(error),
      "operation_key": claim.operationKey,
    });
  }
}
