import type { z } from "zod";

import type { EmployeeEntitlementAuthority } from "../identity-provisioning/employee-entitlement-policy.ts";
import { reserveIdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import {
  type ActiveResourceLease,
  resourceLeaseKey,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type { IGoogleGroupsClient } from "../org-sync/google-groups-client.ts";
import { logErrorEvent, logEvent } from "../shared/log-event.ts";
import {
  MAX_PAGERDUTY_READINESS_IDENTITIES,
  PagerDutyReadinessSchema,
} from "../workspace-directory/pagerduty-readiness-contracts.ts";
import type {
  IPagerDutyLicenseReader,
  IPagerDutyTeamClient,
  IPagerDutyTeamReader,
} from "../workspace-directory/pagerduty-team-client.ts";
import {
  type PagerDutyTeamSyncSettings,
  PagerDutyTeamSyncSettingsSchema,
} from "../workspace-directory/pagerduty-team-config.ts";
import {
  type AuditedPagerDutyTeamPlanSchema,
  type CompletePagerDutyTeamAuditInput,
  pagerDutyMissingUsers,
  pagerDutyTeamActionIsConverged,
  pagerDutyTeamActionIsRecoverable,
  pagerDutyTeamActionPreconditionMatches,
  pagerDutyTeamActionsEqual,
  type PagerDutyTeamAuditInput,
  type PagerDutyTeamWritableAction,
  type PagerDutyTeamWritableActionSchema,
  planPagerDutyTeamSync,
} from "../workspace-directory/pagerduty-team-sync.ts";
import type { WorkspaceProviderExecution } from "./provider-execution.ts";
import type {
  ReviewedActionContext,
  ReviewedActionState,
} from "./reviewed-action-context.ts";
import {
  type ReviewedPagerDutyTeam,
  ReviewedPagerDutyTeamSchema,
} from "./reviewed-pagerduty-team.ts";
const PAGERDUTY_APPLY_LEASE_KEY = resourceLeaseKey(
  "workspace-directory/pagerduty/team-membership",
);
const PAGERDUTY_APPLY_LEASE_MS = 30 * 60 * 1000;
const PAGERDUTY_APPLY_MIN_HEADROOM_MS = 12 * 60 * 1000;
const SIGNED_PARENT_REQUIRED = "pagerduty_team_sync_signed_parent_required";
const WRITE_TOKEN_UNCONFIGURED = "pagerduty_team_sync_write_token_unconfigured";
const PAGERDUTY_LEASE_REPOSITORY_MISSING =
  "pagerduty_team_sync_lease_repository_missing";
export interface PagerDutyTeamServiceDependencies {
  directory: Pick<IGoogleDirectoryClient, "listAllUsers">;
  employeeEntitlementAuthority: () => Promise<EmployeeEntitlementAuthority>;
  groups: Pick<IGoogleGroupsClient, "listGroups">;
  leaseRepository?: ResourceLeaseRepository;
  logError?: typeof logErrorEvent;
  pagerDuty: IPagerDutyTeamReader | null;
  pagerDutyLicenses?: IPagerDutyLicenseReader | null;
  pagerDutyWriter?: IPagerDutyTeamClient | null;
  settings: PagerDutyTeamSyncSettings;
}
export interface PagerDutyTeamParentExecution extends Extract<
  ReviewedActionContext<PagerDutyTeamWritableAction>,
  {
    mode: "parent";
  }
> {
  assertFinalSourceAuthority(): Promise<void>;
}
export interface PagerDutyTeamServiceContract {
  readiness(): Promise<z.output<typeof PagerDutyReadinessSchema>>;
  applyReviewed(
    reviewed: ReviewedPagerDutyTeam,
    parent: PagerDutyTeamParentExecution,
  ): Promise<"busy" | "completed">;
  auditPlan(
    correlationId?: string,
  ): Promise<z.output<typeof AuditedPagerDutyTeamPlanSchema>>;
  readReviewed(reviewed: ReviewedPagerDutyTeam): Promise<ReviewedActionState>;
}
function requireDependency<T>(value: null | T | undefined, message: string): T {
  if (value === null || value === undefined) throw new Error(message);
  return value;
}

class PagerDutyTeamPrewriteDriftError extends Error {
  constructor() {
    super("pagerduty_team_sync_prewrite_drift");
    this.name = "PagerDutyTeamPrewriteDriftError";
  }
}
class PagerDutyTeamReadbackError extends Error {
  constructor() {
    super("pagerduty_team_sync_readback_failed");
    this.name = "PagerDutyTeamReadbackError";
  }
}
export class PagerDutyTeamService implements PagerDutyTeamServiceContract {
  readonly #execution: WorkspaceProviderExecution;
  constructor(
    mode: WorkspaceProviderExecution,
    dependencies: PagerDutyTeamServiceDependencies,
  ) {
    this.#execution = mode;
    this.#dependencies = {
      ...dependencies,
      settings: PagerDutyTeamSyncSettingsSchema.parse(dependencies.settings),
    };
    this.#logError = dependencies.logError ?? logErrorEvent;
  }
  readonly #dependencies: PagerDutyTeamServiceDependencies;
  readonly #logError: typeof logErrorEvent;
  async readReviewed(
    reviewed: ReviewedPagerDutyTeam,
  ): Promise<ReviewedActionState> {
    const original = ReviewedPagerDutyTeamSchema.parse(reviewed);
    const writer = requireDependency(
      this.#dependencies.pagerDutyWriter,
      WRITE_TOKEN_UNCONFIGURED,
    );
    const input = await this.#readCompleteInput(writer, original.reviewId);
    const current = await planPagerDutyTeamSync(input);
    if (
      current.status === "ready" &&
      current.planHash === original.expectedPlanHash &&
      current.actions.some((action) =>
        pagerDutyTeamActionsEqual(action, original.action),
      )
    )
      return "pending";
    return (await pagerDutyTeamActionIsRecoverable(
      input,
      original.action,
      original.expectedPlanHash,
    ))
      ? "converged"
      : "drifted";
  }
  async applyReviewed(
    reviewed: ReviewedPagerDutyTeam,
    parent: PagerDutyTeamParentExecution,
  ) {
    const original = ReviewedPagerDutyTeamSchema.parse(reviewed);
    if (this.#execution.kind !== "parent" || !parent.identityBudget.required)
      throw new Error(SIGNED_PARENT_REQUIRED);
    await parent.verifyPreannouncement(original);
    return this.#applySerialized(
      original.action,
      original.expectedPlanHash,
      original.reviewId,
      crypto.randomUUID(),
      parent,
    );
  }
  async readiness() {
    const reader = requireDependency(
      this.#dependencies.pagerDuty,
      "pagerduty_readiness_source_unconfigured",
    );
    const input = await this.#readCompleteInput(reader, crypto.randomUUID());
    const audit = await planPagerDutyTeamSync(input);
    const missing = pagerDutyMissingUsers(input);
    const licenseReader = this.#dependencies.pagerDutyLicenses;
    const licensing =
      licenseReader === null || licenseReader === undefined
        ? null
        : await licenseReader.licensing().catch(() => {
            this.#logError("pagerduty_team_sync.license_read_failed", {
              "error_code": "license_evidence_unavailable",
            });
            return null;
          });
    const credentialEvidence =
      licenseReader === null || licenseReader === undefined
        ? "missing"
        : licensing === null
          ? "unavailable"
          : "read-verified";
    return PagerDutyReadinessSchema.parse({
      mutationDisabled: this.#execution.kind !== "parent",
      writesAttempted: 0,
      credentialEvidence,
      writePermissionEvidence: "unverified",
      paidCapacity: "unknown",
      sourceComplete: audit.diagnostics.every(
        ({ code, severity }) =>
          severity !== "error" || code === "pagerduty-user-missing",
      ),
      missingUserCount: missing.length,
      missingUsersTruncated:
        missing.length > MAX_PAGERDUTY_READINESS_IDENTITIES,
      missingUsers: missing.slice(0, MAX_PAGERDUTY_READINESS_IDENTITIES),
      licensing,
      diagnostics: [
        ...audit.diagnostics.map(({ code, severity }) => ({
          code,
          severity: severity === "error" ? "blocker" : "warning",
        })),
        { code: "paid_capacity_unverified", severity: "blocker" },
        ...(credentialEvidence === "read-verified"
          ? []
          : [
              {
                code: `dedicated_credential_${credentialEvidence}`,
                severity: "blocker",
              },
            ]),
      ],
    });
  }
  async auditPlan(correlationId: string = crypto.randomUUID()) {
    const settings = this.#dependencies.settings;
    const pagerDutyReader = this.#dependencies.pagerDuty;
    const credentialConfigured = pagerDutyReader !== null;
    const pagerDuty = pagerDutyReader
      ? await pagerDutyReader.snapshot(
          settings.mappings.map(({ pagerDutyTeamId }) => pagerDutyTeamId),
        )
      : undefined;
    if (settings.mappings.length === 0) {
      return planPagerDutyTeamSync({
        credentialConfigured,
        mappings: settings.mappings,
        mutationsDisabled: this.#execution.kind !== "parent",
        reviewId: correlationId,
        ...(!(pagerDuty === undefined) && { pagerDuty }),
      });
    }
    const runId = `pagerduty-team-sync:${correlationId}`;
    const [googleUsers, googleGroups, employeeEntitlementAuthority] =
      await Promise.all([
        this.#dependencies.directory.listAllUsers(runId),
        this.#dependencies.groups.listGroups(
          settings.mappings.map(({ googleGroupEmail }) => googleGroupEmail),
          runId,
          undefined,
          false,
        ),
        this.#dependencies.employeeEntitlementAuthority(),
      ]);
    return planPagerDutyTeamSync({
      credentialConfigured,
      employeeEntitlementAuthority,
      googleGroups,
      googleUsers,
      mappings: settings.mappings,
      mutationsDisabled: this.#execution.kind !== "parent",
      reviewId: correlationId,
      ...(!(pagerDuty === undefined) && { pagerDuty }),
    });
  }
  async #applySerialized(
    action: z.output<typeof PagerDutyTeamWritableActionSchema>,
    expectedPlanHash: string,
    reviewId: string,
    correlationId: string,
    parent: PagerDutyTeamParentExecution,
  ): Promise<"busy" | "completed"> {
    const leaseRepository = requireDependency(
      this.#dependencies.leaseRepository,
      PAGERDUTY_LEASE_REPOSITORY_MISSING,
    );
    const execution = await withResourceLease(
      leaseRepository,
      PAGERDUTY_APPLY_LEASE_KEY,
      PAGERDUTY_APPLY_LEASE_MS,
      async (lease) => {
        await leaseRepository.assertActive(
          lease,
          PAGERDUTY_APPLY_MIN_HEADROOM_MS,
        );
        await this.#apply(
          action,
          expectedPlanHash,
          reviewId,
          correlationId,
          lease,
          leaseRepository,
          parent,
        );
      },
    );
    if (execution.kind === "busy") {
      logEvent("pagerduty_team_sync.apply_busy", {
        "action_type": action.type,
        "correlation_id": correlationId,
        "plan_hash_prefix": expectedPlanHash.slice(0, 12),
      });
      return "busy";
    }
    return "completed";
  }
  async #apply(
    action: z.output<typeof PagerDutyTeamWritableActionSchema>,
    expectedPlanHash: string,
    reviewId: string,
    correlationId: string,
    lease: ActiveResourceLease,
    leaseRepository: ResourceLeaseRepository,
    parent: PagerDutyTeamParentExecution,
  ): Promise<void> {
    const writer = requireDependency(
      this.#dependencies.pagerDutyWriter,
      WRITE_TOKEN_UNCONFIGURED,
    );
    const input = await this.#readCompleteInput(writer, reviewId);
    await this.#verifyOrApplyProviderState(
      input,
      action,
      expectedPlanHash,
      lease,
      leaseRepository,
      writer,
      parent,
    );
    logEvent("pagerduty_team_sync.provider_verified", {
      "action_type": action.type,
      "correlation_id": correlationId,
      "pagerduty_team_id": action.pagerDutyTeamId,
      "pagerduty_user_id": action.pagerDutyUserId,
      "plan_hash_prefix": expectedPlanHash.slice(0, 12),
    });
  }
  async #verifyOrApplyProviderState(
    input: CompletePagerDutyTeamAuditInput,
    action: PagerDutyTeamWritableAction,
    expectedPlanHash: string,
    lease: ActiveResourceLease,
    leaseRepository: ResourceLeaseRepository,
    writer: IPagerDutyTeamClient,
    parent: PagerDutyTeamParentExecution,
  ): Promise<void> {
    const current = await planPagerDutyTeamSync(input);
    const actionStillPlanned = current.actions.some((candidate) =>
      pagerDutyTeamActionsEqual(candidate, action),
    );
    if (
      current.status !== "ready" ||
      current.planHash !== expectedPlanHash ||
      !actionStillPlanned
    ) {
      if (
        await pagerDutyTeamActionIsRecoverable(input, action, expectedPlanHash)
      )
        return;
      throw new PagerDutyTeamPrewriteDriftError();
    }
    await leaseRepository.assertActive(lease, PAGERDUTY_APPLY_MIN_HEADROOM_MS);
    await reserveIdentityWriteBudget(
      parent.identityBudget,
      action.googleUserId,
    );
    const before = await writer.getTeamMembership(
      action.pagerDutyTeamId,
      action.pagerDutyUserId,
    );
    if (!pagerDutyTeamActionPreconditionMatches(action, before)) {
      throw new PagerDutyTeamPrewriteDriftError();
    }
    await writer.putTeamMembership(
      action.pagerDutyTeamId,
      action.pagerDutyUserId,
      action.desiredPagerDutyRole,
      async () => {
        await parent.assertWriteAuthority();
        const fresh = await planPagerDutyTeamSync(
          await this.#readCompleteInput(writer, input.reviewId),
        );
        if (
          fresh.status !== "ready" ||
          fresh.planHash !== expectedPlanHash ||
          !fresh.actions.some((candidate) =>
            pagerDutyTeamActionsEqual(candidate, action),
          )
        )
          throw new PagerDutyTeamPrewriteDriftError();
        await leaseRepository.assertActive(
          lease,
          PAGERDUTY_APPLY_MIN_HEADROOM_MS,
        );
        await parent.assertFinalSourceAuthority();
        const source = await this.#readCompleteInput(
          writer,
          input.reviewId,
          input.pagerDuty,
        );
        const final = await planPagerDutyTeamSync(source);
        if (
          final.status !== "ready" ||
          final.planHash !== expectedPlanHash ||
          !final.actions.some((candidate) =>
            pagerDutyTeamActionsEqual(candidate, action),
          )
        )
          throw new PagerDutyTeamPrewriteDriftError();
        parent.assertFreshPlan();
        if (Date.now() >= lease.expiresAtMs - PAGERDUTY_APPLY_MIN_HEADROOM_MS)
          throw new PagerDutyTeamPrewriteDriftError();
      },
    );
    await leaseRepository.assertActive(lease);
    const after = await writer.getTeamMembership(
      action.pagerDutyTeamId,
      action.pagerDutyUserId,
    );
    if (!pagerDutyTeamActionIsConverged(action, after))
      throw new PagerDutyTeamReadbackError();
  }
  async #readCompleteInput(
    writer: IPagerDutyTeamReader,
    reviewId: string,
    pinnedPagerDuty?: CompletePagerDutyTeamAuditInput["pagerDuty"],
  ) {
    const settings = this.#dependencies.settings;
    const runId = `pagerduty-team-sync:${crypto.randomUUID()}`;
    const [googleGroups, employeeEntitlementAuthority, pagerDuty] =
      await Promise.all([
        this.#dependencies.groups.listGroups(
          settings.mappings.map(({ googleGroupEmail }) => googleGroupEmail),
          runId,
          undefined,
          false,
        ),
        this.#dependencies.employeeEntitlementAuthority(),
        pinnedPagerDuty ??
          writer.snapshot(
            settings.mappings.map(({ pagerDutyTeamId }) => pagerDutyTeamId),
          ),
      ]);
    const googleUsers = await this.#dependencies.directory.listAllUsers(runId);
    return {
      credentialConfigured: true,
      employeeEntitlementAuthority,
      googleGroups,
      googleUsers,
      mappings: settings.mappings,
      mutationsDisabled: false,
      pagerDuty,
      reviewId,
    } satisfies PagerDutyTeamAuditInput & {
      employeeEntitlementAuthority: NonNullable<
        PagerDutyTeamAuditInput["employeeEntitlementAuthority"]
      >;
      googleGroups: NonNullable<PagerDutyTeamAuditInput["googleGroups"]>;
      googleUsers: NonNullable<PagerDutyTeamAuditInput["googleUsers"]>;
      pagerDuty: NonNullable<PagerDutyTeamAuditInput["pagerDuty"]>;
    };
  }
}

export type PagerDutyTeamExecutionPort = Omit<
  PagerDutyTeamServiceContract,
  "readiness"
>;
