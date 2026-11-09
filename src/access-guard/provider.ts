import { z } from "zod";

import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { ProviderReadinessError } from "../provider-readiness.ts";
import { linearSuspensionBlocker } from "./linear-suspension-blocker.ts";
import {
  type AccessDiagnostic,
  type AccessGuardPlan,
  AccessGuardPlanSchema,
  type DownstreamAccount,
  DownstreamAccountSchema,
  type EmailProviderName,
  type GitHubAccessRead,
  GitHubAccessReadSchema,
  normalizeEmail,
  ProviderNameSchema,
  type ProviderSnapshot,
  ProviderSnapshotSchema,
} from "./model.ts";

const DiagnosticCodeSchema = z.string();

export interface EmailAccessAuditProvider {
  listAccounts(runId: string): Promise<readonly DownstreamAccount[]>;
  name: EmailProviderName;
}

export interface GitHubAccessAuditProvider {
  name: "github";
  readAccess(runId: string): Promise<GitHubAccessRead>;
}

export type AccessAuditProvider =
  | EmailAccessAuditProvider
  | GitHubAccessAuditProvider;

export interface AccessEnforcementProvider extends EmailAccessAuditProvider {
  getAccount(accountId: string, correlationId: string): Promise<unknown>;
  suspendAccount(
    accountId: string,
    correlationId: string,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<void>;
}

export interface LinearSuspensionParentContext {
  assertFreshPlan(): void;
  assertWriteAuthority(action: {
    accountId: string;
    email: string;
    googleUserId?: string;
  }): Promise<void>;
}

export interface LinearSuspensionWriteContext extends LinearSuspensionParentContext {
  assertFinalSourceAuthority(): Promise<void>;
}

export class LinearSuspensionPreflightError extends Error {
  override name = "LinearSuspensionPreflightError";
}

export async function captureProviderSnapshot(
  provider: AccessAuditProvider,
  runId: string,
): Promise<ProviderSnapshot> {
  const name = ProviderNameSchema.parse(provider.name);
  try {
    if (provider.name === "github") {
      const captured = GitHubAccessReadSchema.parse(
        await provider.readAccess(runId),
      );
      return ProviderSnapshotSchema.parse({
        ...captured,
        ok: true,
        provider: name,
      });
    }
    const accounts = DownstreamAccountSchema.array().parse(
      await provider.listAccounts(runId),
    );
    return ProviderSnapshotSchema.parse({ accounts, ok: true, provider: name });
  } catch (error) {
    if (error instanceof ProviderReadinessError) {
      return ProviderSnapshotSchema.parse({
        ok: false,
        provider: name,
        readiness: error.context,
      });
    }
    return ProviderSnapshotSchema.parse({
      errorCode: safeErrorCode(error),
      ok: false,
      provider: name,
    });
  }
}

export type EnforcementResult =
  | {
      accountId: string;
      errorCode: string;
      outcome: "failed_closed";
      provider: "linear";
    }
  | { accountId: string; outcome: "already_inactive"; provider: "linear" }
  | {
      accountId: string;
      outcome: "suspended_and_verified";
      provider: "linear";
    };

export function settleLinearEnforcement(
  plan: AccessGuardPlan,
  results: EnforcementResult[],
): AccessGuardPlan {
  const plannedIds = new Set(plan.actions.map((action) => action.accountId));
  const resultCounts = new Map<string, number>();
  for (const result of results) {
    resultCounts.set(
      result.accountId,
      (resultCounts.get(result.accountId) ?? 0) + 1,
    );
  }
  const resultContractDiagnostics: AccessDiagnostic[] = [];
  for (const accountId of plannedIds) {
    if (resultCounts.get(accountId) === 1) continue;
    resultContractDiagnostics.push({
      code: "provider_error",
      context: {
        "account_id": accountId,
        "error_code": "missing_or_duplicate_enforcement_result",
      },
      level: "error",
      message:
        "Linear enforcement results did not exactly cover the planned action",
      provider: "linear",
    });
  }
  for (const [accountId, count] of resultCounts) {
    if (plannedIds.has(accountId) && count === 1) continue;
    resultContractDiagnostics.push({
      code: "provider_error",
      context: {
        "account_id": accountId,
        "error_code": "unexpected_or_duplicate_enforcement_result",
      },
      level: "error",
      message:
        "Linear enforcement returned an unexpected or duplicate action result",
      provider: "linear",
    });
  }
  const verifiedAccountIds = new Set(
    results.flatMap((result) =>
      result.outcome === "failed_closed" ||
      resultCounts.get(result.accountId) !== 1 ||
      !plannedIds.has(result.accountId)
        ? []
        : [result.accountId],
    ),
  );
  const failedDiagnostics = results.flatMap((result): AccessDiagnostic[] =>
    result.outcome === "failed_closed"
      ? [
          {
            code: "provider_error",
            context: {
              "account_id": result.accountId,
              "error_code": result.errorCode,
            },
            level: "error",
            message:
              "Linear suspension failed closed; the critical issue remains open",
            provider: "linear",
          },
        ]
      : [],
  );
  const enforcementDiagnostics = [
    ...resultContractDiagnostics,
    ...failedDiagnostics,
  ];
  const enforcementErrorCodes = [
    ...new Set(
      enforcementDiagnostics.map((diagnostic) => {
        const errorCode = diagnostic.context["error_code"];
        const parsedCode = DiagnosticCodeSchema.safeParse(errorCode);
        return parsedCode.success ? parsedCode.data : diagnostic.code;
      }),
    ),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  const linearCoverageIssue =
    enforcementDiagnostics.length > 0 &&
    plan.issues.every(
      (issue) =>
        issue.kind !== "coverage_failure" || issue.provider !== "linear",
    )
      ? [
          {
            details: { "error_codes": enforcementErrorCodes.join(",") },
            id: `c:linear:${enforcementErrorCodes.join("+")}`,
            kind: "coverage_failure" as const,
            provider: "linear" as const,
            summary:
              "linear access-audit coverage is incomplete; automatic writes are blocked",
          },
        ]
      : [];
  return AccessGuardPlanSchema.parse({
    ...plan,
    actions: [],
    diagnostics: [...plan.diagnostics, ...enforcementDiagnostics],
    issues: [
      ...plan.issues.filter(
        (issue) =>
          issue.provider !== "linear" ||
          issue.kind === "coverage_failure" ||
          !verifiedAccountIds.has(issue.details["account_id"] ?? ""),
      ),
      ...linearCoverageIssue,
    ],
  });
}

export async function enforceLinearSuspension(
  provider: AccessEnforcementProvider,
  expected: { accountId: string; email: string; googleUserId?: string },
  runId: string,
  identityBudget?: IdentityWriteBudget,
  writeContext?: LinearSuspensionWriteContext,
): Promise<EnforcementResult> {
  if (provider.name !== "linear") {
    return {
      accountId: expected.accountId,
      errorCode: "unsupported_provider",
      outcome: "failed_closed",
      provider: "linear",
    };
  }
  try {
    return await executeLinearSuspension(
      provider,
      expected,
      runId,
      identityBudget,
      writeContext,
    );
  } catch (error) {
    return {
      accountId: expected.accountId,
      errorCode:
        error instanceof Error ? error.message.slice(0, 120) : "unknown_error",
      outcome: "failed_closed",
      provider: "linear",
    };
  }
}

function safeErrorCode(error: unknown): string {
  if (!(error instanceof Error)) return "unknown_error";
  const normalized = error.message
    .toLocaleLowerCase("en-US")
    .replaceAll(/[^a-z0-9:_-]+/gu, "_")
    .slice(0, 100);
  return normalized || error.name.toLocaleLowerCase("en-US") || "unknown_error";
}

async function executeLinearSuspension(
  provider: AccessEnforcementProvider,
  expected: { accountId: string; email: string; googleUserId?: string },
  runId: string,
  identityBudget: IdentityWriteBudget | undefined,
  writeContext: LinearSuspensionWriteContext | undefined,
): Promise<EnforcementResult> {
  const before = await readLinearSuspensionTarget(provider, expected, runId);
  if (!before.active) {
    return {
      accountId: before.id,
      outcome: "already_inactive",
      provider: "linear",
    };
  }
  assertLinearSuspensionParentContext(identityBudget, writeContext);
  await reserveIdentityWriteBudget(identityBudget, expected.googleUserId);
  if (identityBudget?.required === true) {
    const fresh = await readLinearSuspensionTarget(provider, expected, runId);
    if (!fresh.active)
      return {
        accountId: fresh.id,
        outcome: "already_inactive",
        provider: "linear",
      };
  }
  let writeError: Error | undefined;
  const assertFinalWriteAuthority = finalLinearSuspensionGuard(
    provider,
    expected,
    runId,
    writeContext,
  );
  try {
    await dispatchLinearSuspension(
      provider,
      before.id,
      runId,
      assertFinalWriteAuthority,
    );
  } catch (error) {
    if (error instanceof LinearSuspensionPreflightError) throw error;
    writeError =
      error instanceof Error
        ? error
        : new Error("linear_suspend_unknown_error");
  }
  const after = DownstreamAccountSchema.parse(
    await provider.getAccount(before.id, runId),
  );
  if (
    after.id !== before.id ||
    normalizeEmail(after.email) !== normalizeEmail(before.email)
  ) {
    throw new Error("identity_changed_after_write");
  }
  if (after.active) {
    if (writeError) throw writeError;
    throw new Error("suspension_not_observed");
  }
  return {
    accountId: after.id,
    outcome: "suspended_and_verified",
    provider: "linear",
  };
}

function dispatchLinearSuspension(
  provider: AccessEnforcementProvider,
  accountId: string,
  correlationId: string,
  assertFinalWriteAuthority: (() => Promise<void>) | undefined,
): Promise<void> {
  return assertFinalWriteAuthority === undefined
    ? provider.suspendAccount(accountId, correlationId)
    : provider.suspendAccount(
        accountId,
        correlationId,
        assertFinalWriteAuthority,
      );
}

function finalLinearSuspensionGuard(
  provider: AccessEnforcementProvider,
  expected: { accountId: string; email: string; googleUserId?: string },
  runId: string,
  writeContext: LinearSuspensionWriteContext | undefined,
): (() => Promise<void>) | undefined {
  if (writeContext === undefined) return undefined;
  return async () => {
    try {
      await writeContext.assertWriteAuthority(expected);
      const current = await readLinearSuspensionTarget(
        provider,
        expected,
        runId,
      );
      if (!current.active) throw new Error("linear_suspension_target_changed");
      await writeContext.assertFinalSourceAuthority();
      writeContext.assertFreshPlan();
    } catch (error) {
      throw new LinearSuspensionPreflightError(
        "linear_suspension_final_preflight_denied",
        {
          cause: error,
        },
      );
    }
  };
}

function assertLinearSuspensionParentContext(
  identityBudget: IdentityWriteBudget | undefined,
  writeContext: LinearSuspensionWriteContext | undefined,
): void {
  if (identityBudget?.required === true && writeContext === undefined)
    throw new Error("linear_suspension_parent_context_required");
  if (writeContext !== undefined && identityBudget?.required !== true)
    throw new Error("linear_suspension_parent_budget_required");
}

async function readLinearSuspensionTarget(
  provider: AccessEnforcementProvider,
  expected: { accountId: string; email: string; googleUserId?: string },
  runId: string,
): Promise<DownstreamAccount> {
  const current = DownstreamAccountSchema.parse(
    await provider.getAccount(expected.accountId, runId),
  );
  if (
    current.id !== expected.accountId ||
    normalizeEmail(current.email) !== normalizeEmail(expected.email)
  )
    throw new Error("identity_changed_before_write");
  if (current.active) {
    const blocker = linearSuspensionBlocker(current, expected.googleUserId);
    if (blocker !== undefined) throw new Error(blocker);
  }
  return current;
}
