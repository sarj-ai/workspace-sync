import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { logEvent } from "../shared/log-event.ts";
import { computeAccessGuardPlan } from "./compute.ts";
import {
  type AccessGuardAnchor,
  AccessGuardAnchorSchema,
  accessGuardSlackMetadata,
  canAdvanceAccessGuardAnchor,
  canApplyLinearPlan,
  reconcileIssueSet,
  shouldRunAccessGuard,
} from "./issue-set.ts";
import type { LinearAccessProvider } from "./linear-provider.ts";
import {
  type AccessGuardAuditOptions,
  type AccessGuardPlan,
  AccessGuardPlanSchema,
  DownstreamAccountSchema,
  type LinearAccessManagedSlice,
  LinearAccessManagedSliceSchema,
  normalizeEmail,
} from "./model.ts";
import {
  type AccessAuditProvider,
  captureProviderSnapshot,
  enforceLinearSuspension,
  type LinearSuspensionWriteContext,
  settleLinearEnforcement,
} from "./provider.ts";
import { readAccessGuardAnchor } from "./read-access-guard-anchor.ts";
import type { SlackAccessClient } from "./slack-access-client.ts";

export interface AccessGuardReport {
  actions: number;
  complete: boolean;
  issues: number;
  newIssues: number;
  runId: string;
  skipped: boolean;
}

export interface IAccessGuardService {
  applyLinearPlan(
    plan: AccessGuardPlan,
    identityBudget?: IdentityWriteBudget,
    writeContext?: LinearSuspensionWriteContext,
  ): Promise<number>;
  audit(
    googleUsers: readonly GoogleDirectoryUser[],
    options?: AccessGuardAuditOptions,
  ): Promise<AccessGuardPlan>;
  readLinearManagedSlice(
    actions: AccessGuardPlan["actions"],
  ): Promise<LinearAccessManagedSlice>;
  report(plan: AccessGuardPlan, now?: Date): Promise<AccessGuardReport>;
  run(
    googleUsers: readonly GoogleDirectoryUser[],
    now?: Date,
  ): Promise<AccessGuardReport>;
}

export class AccessGuardService implements IAccessGuardService {
  readonly #config: {
    allowedEmptyDepartmentGoogleUserIds: string[];
    allowedEmptyManagerGoogleUserIds: string[];
    excludedGoogleUserIds: string[];
    protectedDepartedGoogleUserIds: string[];
    maxReviewedLinearSuspensions: number;
    minimumGoogleUsers: number;
    minimumProviderAccounts: Partial<
      Record<AccessAuditProvider["name"], number>
    >;
    rootGoogleUserIds: string[];
  };
  readonly #linear: LinearAccessProvider;
  readonly #providers: readonly AccessAuditProvider[];
  readonly #slack: SlackAccessClient;

  constructor(
    slack: SlackAccessClient,
    linear: LinearAccessProvider,
    config: {
      allowedEmptyDepartmentGoogleUserIds: string[];
      allowedEmptyManagerGoogleUserIds?: string[];
      excludedGoogleUserIds: string[];
      protectedDepartedGoogleUserIds?: string[];
      maxReviewedLinearSuspensions?: number;
      minimumGoogleUsers?: number;
      minimumProviderAccounts?: Partial<
        Record<AccessAuditProvider["name"], number>
      >;
      rootGoogleUserIds: string[];
    },
    additionalProviders: readonly AccessAuditProvider[] = [],
  ) {
    this.#config = {
      ...config,
      allowedEmptyManagerGoogleUserIds:
        config.allowedEmptyManagerGoogleUserIds ?? [],
      protectedDepartedGoogleUserIds:
        config.protectedDepartedGoogleUserIds ?? [],
      maxReviewedLinearSuspensions: config.maxReviewedLinearSuspensions ?? 0,
      minimumGoogleUsers: config.minimumGoogleUsers ?? 1,
      minimumProviderAccounts: config.minimumProviderAccounts ?? {},
    };
    this.#linear = linear;
    this.#slack = slack;
    this.#providers = [slack, linear, ...additionalProviders].map(
      readOnlyInventoryFacade,
    );
  }

  async audit(
    googleUsers: readonly GoogleDirectoryUser[],
    options: AccessGuardAuditOptions = {},
  ): Promise<AccessGuardPlan> {
    const runId = crypto.randomUUID();
    const providerSnapshots = await Promise.all(
      this.#providers.map(async (provider) =>
        captureProviderSnapshot(provider, runId),
      ),
    );
    const plan = computeAccessGuardPlan({
      ...options,
      config: {
        ...this.#config,
        requiredProviders: this.#providers.map((provider) => provider.name),
      },
      googleUsers,
      providerSnapshots,
    });
    logEvent("access_guard.audit_completed", {
      actions: plan.actions.length,
      diagnostics: plan.diagnostics.length,
      issues: plan.issues.length,
      "run_id": runId,
    });
    return plan;
  }

  async applyLinearPlan(
    rawPlan: AccessGuardPlan,
    identityBudget?: IdentityWriteBudget,
    writeContext?: LinearSuspensionWriteContext,
  ): Promise<number> {
    const plan = AccessGuardPlanSchema.parse(rawPlan);
    if (!canApplyLinearPlan(plan)) {
      throw new Error("access_guard_plan_has_blocking_diagnostics");
    }
    if (plan.actions.length > this.#config.maxReviewedLinearSuspensions) {
      throw new Error("access_guard_linear_suspension_cap_exceeded");
    }
    assertUniqueLinearActions(plan.actions);
    const runId = crypto.randomUUID();
    const results = await Promise.all(
      plan.actions.map(async (action) =>
        enforceLinearSuspension(
          this.#linear,
          action,
          runId,
          identityBudget,
          writeContext,
        ),
      ),
    );
    const settled = settleLinearEnforcement(plan, results);
    if (!canApplyLinearPlan(settled)) {
      throw new Error("access_guard_linear_enforcement_failed_closed");
    }
    return results.length;
  }

  async readLinearManagedSlice(
    actions: AccessGuardPlan["actions"],
  ): Promise<LinearAccessManagedSlice> {
    assertUniqueLinearActions(actions);
    const runId = crypto.randomUUID();
    const accounts = await Promise.all(
      actions.map(async (action) => {
        const account = DownstreamAccountSchema.parse(
          await this.#linear.getAccount(action.accountId, runId),
        );
        return {
          accountId: account.id,
          active: account.active,
          email: normalizeEmail(account.email),
        };
      }),
    );
    return LinearAccessManagedSliceSchema.parse(
      accounts.toSorted((left, right) =>
        left.accountId.localeCompare(right.accountId),
      ),
    );
  }

  async run(
    googleUsers: readonly GoogleDirectoryUser[],
    now = new Date(),
  ): Promise<AccessGuardReport> {
    return this.report(await this.audit(googleUsers), now);
  }

  async report(
    rawPlan: AccessGuardPlan,
    now = new Date(),
  ): Promise<AccessGuardReport> {
    const plan = AccessGuardPlanSchema.parse(rawPlan);
    const runId = crypto.randomUUID();
    const previous = await readAccessGuardAnchor(this.#slack, runId);
    const delivery = accessGuardDeliveryAttempt(plan, previous, now);
    if (!delivery.hasNewIssues && !shouldRunAccessGuard(now, previous)) {
      logEvent("access_guard.skipped", { reason: "cadence", "run_id": runId });
      return {
        actions: 0,
        complete: true,
        issues: previous?.issueIds.length ?? 0,
        newIssues: 0,
        runId,
        skipped: true,
      };
    }
    logEvent("access_guard.report_started", { "run_id": runId });
    const plannedActions = plan.actions.length;
    const complete = canAdvanceAccessGuardAnchor(plan);
    const reconciliation = reconcileIssueSet(
      previous,
      plan.issues,
      now,
      complete ? "complete" : "incomplete",
    );
    if (delivery.persistPendingAnchor) {
      await this.#slack.upsertUniqueAnchor({
        metadata: accessGuardSlackMetadata(
          AccessGuardAnchorSchema.parse({
            issueIds: previous?.issueIds ?? [],
            lastAttemptAt: delivery.occurrence,
            lastSuccessAt: previous?.lastSuccessAt ?? null,
            version: 1,
          }),
        ),
        runId,
      });
    }
    await this.#slack.postNewIssues(
      reconciliation.newIssues,
      runId,
      delivery.occurrence,
    );
    await this.#slack.upsertUniqueAnchor({
      metadata: accessGuardSlackMetadata(reconciliation.anchor),
      runId,
    });
    logEvent("access_guard.completed", {
      actions: plannedActions,
      complete,
      diagnostics: plan.diagnostics.length,
      issues: plan.issues.length,
      "new_issues": reconciliation.newIssues.length,
      "provider_attio_accounts": plan.stats.providerAccounts.attio ?? 0,
      "provider_linear_accounts": plan.stats.providerAccounts.linear ?? 0,
      "provider_slack_accounts": plan.stats.providerAccounts.slack ?? 0,
      "run_id": runId,
    });
    return {
      actions: plannedActions,
      complete,
      issues: plan.issues.length,
      newIssues: reconciliation.newIssues.length,
      runId,
      skipped: false,
    };
  }
}

interface AccessGuardDeliveryAttempt {
  hasNewIssues: boolean;
  occurrence: string;
  persistPendingAnchor: boolean;
}

function accessGuardDeliveryAttempt(
  plan: AccessGuardPlan,
  previous: AccessGuardAnchor | null,
  now: Date,
): AccessGuardDeliveryAttempt {
  const hasNewIssues =
    previous === null
      ? plan.issues.length > 0
      : plan.issues.some(({ id }) => !previous.issueIds.includes(id));
  const previousAttemptComplete =
    previous !== null &&
    previous.lastSuccessAt !== null &&
    Date.parse(previous.lastSuccessAt) >= Date.parse(previous.lastAttemptAt);
  return {
    hasNewIssues,
    occurrence:
      previous !== null && !previousAttemptComplete
        ? previous.lastAttemptAt
        : now.toISOString(),
    persistPendingAnchor:
      previous === null || (hasNewIssues && previousAttemptComplete),
  };
}

function readOnlyInventoryFacade(
  provider: AccessAuditProvider,
): AccessAuditProvider {
  return provider.name === "github"
    ? Object.freeze({
        name: provider.name,
        readAccess: (runId: string) => provider.readAccess(runId),
      })
    : Object.freeze({
        listAccounts: (runId: string) => provider.listAccounts(runId),
        name: provider.name,
      });
}

function assertUniqueLinearActions(actions: AccessGuardPlan["actions"]): void {
  if (
    new Set(actions.map((action) => action.accountId)).size !== actions.length
  ) {
    throw new Error("access_guard_duplicate_linear_action");
  }
}
