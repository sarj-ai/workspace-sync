import { dequal } from "dequal";
import { z } from "zod";

import type {
  AccessGuardAuditOptions,
  AccessGuardPlan,
} from "../access-guard/model.ts";
import type { LinearSuspensionParentContext } from "../access-guard/provider.ts";
import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { GitHubAccessAuditClient } from "../github-access-audit/git-hub-access-audit-client.ts";
import { projectGoogleDirectoryAuthority } from "../identity-lifecycle/project-google-directory-authority.ts";
import {
  assertDistinctGitHubOrganizationCredentials,
  GitHubOrganizationApiPort,
} from "../identity-provisioning/github-organization-api-port.ts";
import type { GitHubOrganizationWriteContext } from "../identity-provisioning/github-organization-connector.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import {
  fingerprintGithubIdentitySource,
  type GoogleGithubIdentitySeedPlan,
  GoogleGithubIdentitySeedService,
} from "../identity-sync/google-github-identity-seed-service.ts";
import {
  D1ResourceLeaseRepository,
  type ResourceLeaseRepository,
} from "../identity-sync/resource-lease.ts";
import { sha256Hex } from "../operations/canonical.ts";
import {
  OperationContractError,
  OperationSourceError,
} from "../operations/registry.ts";
import { type JsonValue, JsonValueSchema } from "../operations/schemas.ts";
import type {
  OrgChannelSyncRunReport,
  OrgChannelSyncService,
} from "../org-sync/channel-service.ts";
import {
  googleAuthorityFingerprintRecord,
  mergeGoogleDirectoryAuthority,
} from "../org-sync/google-directory-authority.ts";
import { DIRECTORY_READONLY_SCOPE } from "../org-sync/google-directory-client.ts";
import { SarjIdentitySchemaService } from "../org-sync/google-identity-schema.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type {
  ReviewedSlackLifecycleDurableParent,
  ReviewedSlackLifecycleParentContext,
  ReviewedSlackLifecycleRemoval,
} from "../org-sync/reviewed-lifecycle-removal.ts";
import type { OrgSyncRunReport } from "../org-sync/service.ts";
import { logErrorEvent } from "../shared/log-event.ts";
import { sameStringMultiset } from "../shared/same-string-multiset.ts";
import type { TrycompReviewedPlan } from "../trycomp/model.ts";
import { D1WorkspaceLedgerHistoryIndex } from "../workspace-directory/d1-workspace-ledger-history-index.ts";
import { bindWorkspaceLinearParentContext } from "./bind-workspace-linear-parent-context.ts";
import { captureWorkspaceNameBranches } from "./capture-workspace-name-branches.ts";
import {
  SlackGroupsChannelsBranchPlanSchema,
  WORKSPACE_DIRECTORY_ACTION_IDS,
  type WorkspaceDirectoryAuthorizedActionId,
  type WorkspaceDirectoryPlan,
  WorkspaceDirectoryPlanSchema,
} from "./contracts.ts";
import { coordinateSlackIdentityBudget } from "./coordinate-slack-identity-budget.ts";
import {
  assertDriveOrgChartFileId,
  driveOrgChartManagedSlice,
} from "./drive-org-chart-artifact.ts";
import { WORKSPACE_DIRECTORY_FLOW } from "./flow.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import {
  applyManagedGitHubAccess,
  captureManagedGitHubAccessState,
  captureManagedGitHubAuthorityFingerprint,
  readManagedGitHubTargetSlice,
  refreshManagedGitHubDesiredAuthority,
  sameManagedGitHubSelection,
} from "./github-access-managed.ts";
import type { GoogleGroupCleanupServiceContract } from "./google-group-cleanup-service.ts";
import {
  slackGroupsChannelsBeforeSlice,
  slackGroupsChannelsAfterSlice,
  slackProfilesBeforeSlice,
  slackProfilesAfterSlice,
} from "./managed-slices.ts";
import { observeOriginalSlackMembershipTarget } from "./observe-original-slack-membership-target.ts";
import type { PagerDutyTeamExecutionPort } from "./pager-duty-team-service.ts";
import type {
  WorkspaceSyncRuntimeBindings,
  WorkspaceNameServices,
} from "./provider-runtime-ports.ts";
import {
  type GoogleGroupCleanupParentContext,
  ReviewedGoogleGroupCleanupAdapter,
} from "./reviewed-google-group-cleanup-adapter.ts";
import type { ReviewedGoogleGroupCleanupIntent } from "./reviewed-google-group-cleanup.ts";
import {
  type ReviewedLinearSuspension,
  selectReviewedLinearSuspension,
} from "./reviewed-linear-suspension.ts";
import type { ReviewedNameAction } from "./reviewed-name-plan.ts";
import {
  type PagerDutyTeamParentContext,
  ReviewedPagerDutyTeamAdapter,
} from "./reviewed-pager-duty-team-adapter.ts";
import {
  ReviewedSentryWorkspaceAdapter,
  type SentryWorkspaceParentContext,
} from "./reviewed-sentry-workspace-adapter.ts";
import {
  ReviewedWorkspaceNameAdapter,
  type WorkspaceNameParentContext,
} from "./reviewed-workspace-name-adapter.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";
import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";
import { selectedSlackMembershipUserId } from "./selected-slack-membership-user-id.ts";
import { sentryWorkspaceParentConfig } from "./sentry-workspace-parent-config.ts";
import type { SentryWorkspaceExecutionPort } from "./sentry-workspace-service.ts";
import { TrycompAdapter } from "./trycomp-adapter.ts";
import { inspectGithubWriterReadiness } from "./writer-readiness.ts";

const GOOGLE_GITHUB_IDENTITY_SEED_RUNTIME_UNAVAILABLE =
  "google_github_identity_seed_runtime_unavailable";
const GITHUB_ACCESS_KILL_SWITCH_ENGAGED =
  "workspace_directory_github_access_kill_switch_engaged";
const SLACK_CHANNEL_PLAN_HASH_INVALID =
  "workspace_directory_slack_channel_plan_hash_invalid";
const SLACK_PROFILE_PLAN_HASH_INVALID =
  "workspace_directory_slack_profile_plan_hash_invalid";
const IDENTITY_SCHEMA_NOT_SELECTED =
  "workspace_directory_identity_schema_not_selected";
const GITHUB_IDENTITY_SEED_DISABLED =
  "workspace_directory_github_identity_seed_disabled";
export function slackChannelRunError(
  result: Pick<OrgChannelSyncRunReport, "errors" | "status">,
): string {
  if (result.status !== "blocked")
    return `workspace_directory_slack_channel_${result.status}`;
  const message = result.errors.at(-1) ?? "";
  if (message === "Slack token lacks the matching channel invitation scope") {
    return "workspace_directory_slack_channel_invite_scope_missing";
  }
  if (message.includes("approval hash")) {
    return "workspace_directory_slack_channel_approval_mismatch";
  }
  if (message.includes("additions exceed the limit")) {
    return "workspace_directory_slack_channel_addition_limit_blocked";
  }
  if (message.includes("deadline is too close")) {
    return "workspace_directory_slack_channel_deadline_blocked";
  }
  if (message.includes("writes are disabled")) {
    return "workspace_directory_slack_channel_writes_disabled";
  }
  return "workspace_directory_slack_channel_blocked";
}

export interface WorkspaceDirectoryRuntimeOptions {
  applyReviewedTrycomp?: (plan: TrycompReviewedPlan) => Promise<string>;
  channelDatabase?: D1Database;
  channelLeaseRepository?: ResourceLeaseRepository;
  githubIdentityBudget?: IdentityWriteBudget;
  githubParentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => GitHubOrganizationWriteContext;
  googleGroupCleanupParentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => GoogleGroupCleanupParentContext;
  googleGroupCleanupService?: GoogleGroupCleanupServiceContract;
  googleIdentityBudget?: IdentityWriteBudget;
  linearIdentityBudget?: IdentityWriteBudget;
  linearSuspensionParentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => LinearSuspensionParentContext;
  nameRepairParentContext?: (
    reviewed: ReviewedNameAction,
  ) => WorkspaceNameParentContext;
  nameServices?: WorkspaceNameServices;
  pagerDutyIdentityBudget?: IdentityWriteBudget;
  pagerDutyTeamParentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => PagerDutyTeamParentContext;
  pagerDutyTeamService?: PagerDutyTeamExecutionPort;
  readVerifiedTrycompInvitation?: (
    plan: TrycompReviewedPlan,
  ) => Promise<null | string>;
  reviewedSlackLifecycleParentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => ReviewedSlackLifecycleDurableParent;
  scheduledLinearSuspensions?: boolean;
  sentryIdentityBudget?: IdentityWriteBudget;
  sentryParentContext?: (
    plan: WorkspaceDirectoryPlan,
  ) => SentryWorkspaceParentContext;
  sentryService?: SentryWorkspaceExecutionPort;
  slackIdentityBudget?: IdentityWriteBudget;
}
interface IdentityProvisioningDependencies {
  assertGoogleAuthority(
    plan: WorkspaceDirectoryPlan,
  ): Promise<GoogleDirectoryUser[]>;
  identityBudget?: IdentityWriteBudget | undefined;
  identitySchema: Pick<SarjIdentitySchemaService, "applyPlan">;
  identitySeed: null | Pick<
    GoogleGithubIdentitySeedService,
    "applyPlan" | "captureSource"
  >;
  parentOwned?: boolean;
}
function assertRequiredIdentityBudget(
  enabled: boolean,
  budget: IdentityWriteBudget | undefined,
  service: "github" | "google" | "linear" | "slack",
): void {
  if (enabled && budget?.required !== true)
    throw new Error(`workspace_directory_${service}_identity_budget_required`);
}
export async function applyWorkspaceDirectoryIdentityProvisioning(
  plan: WorkspaceDirectoryPlan,
  dependencies: IdentityProvisioningDependencies,
): Promise<string> {
  if (
    dependencies.parentOwned &&
    dependencies.identityBudget?.required !== true
  ) {
    throw new Error("workspace_directory_google_identity_budget_required");
  }
  const identity = plan.branches[5];
  if (identity.schemaPlan.kind === "not-selected") {
    throw new Error(IDENTITY_SCHEMA_NOT_SELECTED);
  }
  await dependencies.assertGoogleAuthority(plan);
  if (identity.githubIdentitySeed.kind === "managed") {
    if (!dependencies.identitySeed) {
      throw new Error(GOOGLE_GITHUB_IDENTITY_SEED_RUNTIME_UNAVAILABLE);
    }
    const sourceFingerprint = await fingerprintGithubIdentitySource(
      await dependencies.identitySeed.captureSource(),
    );
    if (
      sourceFingerprint !== identity.githubIdentitySeed.githubSourceFingerprint
    ) {
      throw new Error("github_identity_source_drift");
    }
  }
  const schemaResult = await dependencies.identitySchema.applyPlan(
    identity.schemaPlan,
  );
  const schemaDetail =
    schemaResult.plan.kind === "unchanged"
      ? "Google SarjIdentity schema was already converged."
      : `Google SarjIdentity schema ${schemaResult.plan.kind} converged and was verified.`;
  if (identity.githubIdentitySeed.kind !== "managed") return schemaDetail;
  if (!dependencies.identitySeed) {
    throw new Error(GOOGLE_GITHUB_IDENTITY_SEED_RUNTIME_UNAVAILABLE);
  }
  const applied = await dependencies.identitySeed.applyPlan(
    identity.githubIdentitySeed,
    dependencies.identityBudget,
  );
  return `${schemaDetail} ${String(applied)} Google GitHub identity mappings converged.`;
}
export function createWorkspaceDirectoryRuntime(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  options: WorkspaceDirectoryRuntimeOptions = {},
): WorkspaceDirectoryRuntime {
  const googleReader = bindings.google(
    "workspace_directory_capture",
    DIRECTORY_READONLY_SCOPE,
  );
  const googleWriter = bindings.google("workspace_directory_reconcile");
  const identitySchema = new SarjIdentitySchemaService(googleWriter);
  const identitySeed = createIdentitySeedService(env, googleWriter);
  const identityExclusionReason =
    env.workspaceDirectoryGithubIdentitySeedEnabled
      ? "action_not_selected"
      : GITHUB_IDENTITY_SEED_DISABLED;
  const trycomp = new TrycompAdapter(
    env,
    () => bindings.trycomp(),
    options.applyReviewedTrycomp,
    options.readVerifiedTrycompInvitation,
  );
  const historyIndex =
    options.channelDatabase === undefined
      ? undefined
      : new D1WorkspaceLedgerHistoryIndex(options.channelDatabase);
  let names = options.nameServices;
  let cleanup = options.googleGroupCleanupService;
  let pagerDuty = options.pagerDutyTeamService;
  let sentry = options.sentryService;
  function sentryService(): SentryWorkspaceExecutionPort {
    if (!env.workspaceDirectoryParentEnabled) {
      throw new Error("workspace_sentry_parent_disabled");
    }
    if (sentry !== undefined) return sentry;
    const leaseRepository =
      options.channelLeaseRepository ??
      (options.channelDatabase === undefined
        ? undefined
        : new D1ResourceLeaseRepository(options.channelDatabase));
    if (leaseRepository === undefined)
      throw new Error("workspace_sentry_lease_required");
    sentry = bindings.sentry(leaseRepository);
    return sentry;
  }
  function pagerDutyService(): PagerDutyTeamExecutionPort {
    if (!env.workspaceDirectoryParentEnabled)
      throw new Error("workspace_pagerduty_teams_parent_disabled");
    if (pagerDuty !== undefined) return pagerDuty;
    const leaseRepository =
      options.channelLeaseRepository ??
      (options.channelDatabase === undefined
        ? undefined
        : new D1ResourceLeaseRepository(options.channelDatabase));
    if (leaseRepository === undefined)
      throw new Error("workspace_pagerduty_teams_lease_required");
    pagerDuty = bindings.pagerDuty(leaseRepository);
    return pagerDuty;
  }
  function cleanupService(): GoogleGroupCleanupServiceContract {
    if (!env.workspaceDirectoryParentEnabled)
      throw new Error("workspace_google_group_cleanup_parent_disabled");
    if (cleanup !== undefined) return cleanup;
    const leaseRepository =
      options.channelLeaseRepository ??
      (options.channelDatabase === undefined
        ? undefined
        : new D1ResourceLeaseRepository(options.channelDatabase));
    if (leaseRepository === undefined)
      throw new Error("workspace_google_group_cleanup_lease_required");
    cleanup = bindings.googleCleanup(leaseRepository);
    return cleanup;
  }
  const namesEnabled = () =>
    env.workspaceDirectoryParentEnabled &&
    !env.orgSyncDisabled &&
    env.orgSyncMode === "live";
  function nameServices(): WorkspaceNameServices {
    if (!namesEnabled())
      throw new Error("workspace_directory_name_parent_disabled");
    if (names !== undefined) return names;
    const leaseRepository =
      options.channelLeaseRepository ??
      (options.channelDatabase === undefined
        ? undefined
        : new D1ResourceLeaseRepository(options.channelDatabase));
    if (leaseRepository === undefined)
      throw new Error("workspace_directory_name_lease_missing");
    names = bindings.names(leaseRepository, captureGoogle, historyIndex);
    return names;
  }
  async function captureGoogle(
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    const runId = crypto.randomUUID();
    const [activeUsers, deletedUsers] = await Promise.all([
      googleReader.listAllUsers(runId, deadlineAt),
      googleReader.listDeletedUsers(runId, deadlineAt),
    ]);
    return mergeGoogleDirectoryAuthority(activeUsers, deletedUsers);
  }
  async function capture(
    includedActionIds:
      | null
      | readonly WorkspaceDirectoryAuthorizedActionId[] = null,
    reviewedSlackLifecycleRemoval?: ReviewedSlackLifecycleRemoval,
    reviewedLinearSuspension?: ReviewedLinearSuspension,
    reviewedGoogleGroupCleanup?: ReviewedGoogleGroupCleanupIntent,
  ): Promise<WorkspaceDirectoryPlan> {
    assertReviewedLifecycleParentEnabled(env, reviewedSlackLifecycleRemoval);
    assertReviewedLifecycleParentEnabled(env, reviewedLinearSuspension);
    const includes = (actionId: WorkspaceDirectoryAuthorizedActionId) =>
      includedActionIds === null || includedActionIds.includes(actionId);
    const users = await captureWorkspaceDirectoryComponent(
      "workspace-directory.google-directory",
      captureGoogle,
    );
    const authorityFingerprint = await captureWorkspaceDirectoryComponent(
      "workspace-directory.authority-fingerprint",
      () => fingerprintGoogleAuthority(users),
    );
    const observedAt = new Date().toISOString();
    const subjects = captureComponentSync(
      "workspace-directory.identity-authority",
      () =>
        users.map((user) => projectGoogleDirectoryAuthority(user, observedAt)),
    );
    const captureIdentitySchemaPlan = () =>
      captureWorkspaceDirectoryIdentitySchema(
        env.workspaceDirectoryGithubIdentitySeedEnabled &&
          includes(WORKSPACE_DIRECTORY_ACTION_IDS.fanout),
        identitySchema,
      );
    const captureGithubIdentitySeedPlan = () =>
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.fanout)
        ? Promise.resolve<GoogleGithubIdentitySeedPlan>({
            kind: "disabled",
            reason: identityExclusionReason,
          })
        : captureWorkspaceDirectoryComponent(
            "workspace-directory.google-github-identity-seed",
            () =>
              captureIdentitySeedPlan(
                env,
                identitySeed,
                users,
                authorityFingerprint,
              ),
          );
    const captureProfilesPlan = async () =>
      env.orgSyncDisabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles)
        ? disabledSlackProfilesPlan(
            env.orgSyncDisabled ? "org_sync_disabled" : "action_not_selected",
          )
        : captureWorkspaceDirectoryComponent(
            "workspace-directory.slack-profiles",
            () => captureProfiles(bindings, env, users),
          );
    const captureChannelsPlan = async () =>
      env.orgChannelSyncDisabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels)
        ? disabledSlackGroupsChannelsPlan(
            env.orgChannelSyncDisabled
              ? "org_channel_sync_disabled"
              : "action_not_selected",
          )
        : captureWorkspaceDirectoryComponent(
            "workspace-directory.slack-groups-channels",
            () =>
              captureChannels(
                bindings,
                env,
                users,
                options.channelDatabase,
                undefined,
                { kind: "new-plan" },
                reviewedSlackLifecycleRemoval,
              ),
          );
    const captureChartPlan = async () =>
      env.orgSyncDisabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.driveOrgChart)
        ? disabledDriveOrgChartPlan(
            env.orgSyncDisabled ? "org_sync_disabled" : "action_not_selected",
          )
        : captureWorkspaceDirectoryComponent(
            "workspace-directory.drive-org-chart",
            () => captureDriveOrgChart(bindings, users),
          );
    const captureGithubPlan = async () => {
      if (!includes(WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess))
        return disabledGitHubAccessPlan("action_not_selected");
      const plan = await captureGithubBranch(bindings, env, users);
      return plan;
    };
    const captureAccessPlan = async () =>
      !getWorkspaceExecutionPolicy().accessGuard.enabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions)
        ? {
            branchId: "access-guard" as const,
            diagnostics: [
              disabledDiagnostic(
                !getWorkspaceExecutionPolicy().accessGuard.enabled
                  ? "access_guard_disabled"
                  : "action_not_selected",
              ),
            ],
            execution: "disabled" as const,
            killSwitchEngaged: true,
            plan: null,
          }
        : captureWorkspaceDirectoryComponent(
            "workspace-directory.access-guard",
            () =>
              captureAccessGuard(
                bindings,
                env,
                users,
                reviewedLinearSuspension,
                options.scheduledLinearSuspensions === true,
              ),
          );
    const {
      access: accessPlan,
      channels: channelPlan,
      chart: chartPlan,
      github: githubPlan,
      identitySeed: githubIdentitySeed,
      profiles: profilePlan,
      schema: schemaPlan,
    } = await captureWorkspaceDirectoryFanout({
      access: captureAccessPlan,
      channels: captureChannelsPlan,
      chart: captureChartPlan,
      github: captureGithubPlan,
      identitySeed: captureGithubIdentitySeedPlan,
      profiles: captureProfilesPlan,
      schema: captureIdentitySchemaPlan,
    });
    const trycompBranch =
      env.workspaceDirectoryTrycompEnabled &&
      includes(WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople)
        ? await captureWorkspaceDirectoryComponent(
            "workspace-directory.trycomp-people",
            () => trycomp.capture(),
          )
        : null;
    const slack = coordinateSlackIdentityBudget(
      profilePlan,
      channelPlan,
      env.workspaceDirectoryParentEnabled,
    );
    let plan = parseWorkspaceDirectoryPlan({
      authorityFingerprint,
      branches: [
        slack.profiles,
        chartPlan,
        slack.channels,
        githubPlan,
        accessPlan,
        {
          branchId: "identity-provisioning",
          diagnostics: [
            ...(schemaPlan.kind === "not-selected"
              ? [disabledDiagnostic(identityExclusionReason)]
              : schemaPlan.kind === "blocked"
                ? schemaPlan.issues.map((message) => ({
                    code: "google_identity_schema_incompatible",
                    message,
                    scope: {
                      actionId: "workspace-directory.fanout",
                      kind: "action" as const,
                    },
                    severity: "blocker" as const,
                  }))
                : [
                    {
                      code: "managed_google_identity_schema",
                      message:
                        "The SarjIdentity schema is bound to the signed plan and verified by readback.",
                      severity: "info" as const,
                    },
                  ]),
            ...githubIdentitySeedDiagnostics(githubIdentitySeed),
            {
              code: "audit_only_connector",
              message:
                "External provider account provisioning remains audit-only; Google SarjIdentity schema and GitHub identity fields use managed exact apply and verification.",
              severity: "info",
            },
          ],
          execution: "managed",
          githubIdentitySeed,
          killSwitchEngaged: false,
          providerExecution: "audit-only",
          schemaPlan,
          subjects: subjects.map((subject) => ({
            authorityRevision: workspaceDirectoryAuthorityRevision(
              subject.googleUserId,
              authorityFingerprint,
            ),
            githubLinked: subject.github.kind === "verified",
            googleUserId: subject.googleUserId,
            lifecycle: subject.lifecycle.kind,
          })),
        },
        ...(trycompBranch === null ? [] : [trycompBranch]),
      ],
      googleUsers: users.length,
      policyVersion: WORKSPACE_DIRECTORY_FLOW.policyVersion,
    });
    plan = await appendCleanupBranch(
      plan,
      includes,
      reviewedGoogleGroupCleanup,
    );
    plan = await appendPagerDutyBranch(plan, includes);
    plan = await appendSentryBranch(plan, includes);
    if (
      !namesEnabled() ||
      (!includes(WORKSPACE_DIRECTORY_ACTION_IDS.slackNames) &&
        !includes(WORKSPACE_DIRECTORY_ACTION_IDS.linearProfiles))
    )
      return plan;
    const nameBranches = await captureWorkspaceDirectoryComponent(
      "workspace-directory.name-repairs",
      () => captureWorkspaceNameBranches(plan, users, nameServices(), includes),
    );
    return parseWorkspaceDirectoryPlan({
      ...plan,
      branches: [...plan.branches, ...nameBranches],
    });
  }
  async function assertGoogleAuthority(
    plan: WorkspaceDirectoryPlan,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]> {
    const users = await captureGoogle(deadlineAt);
    if (
      (await fingerprintGoogleAuthority(users)) !== plan.authorityFingerprint
    ) {
      throw new Error("google_authority_drift");
    }
    return users;
  }
  async function appendCleanupBranch(
    plan: WorkspaceDirectoryPlan,
    includes: (actionId: WorkspaceDirectoryAuthorizedActionId) => boolean,
    reviewed?: ReviewedGoogleGroupCleanupIntent,
  ): Promise<WorkspaceDirectoryPlan> {
    if (
      !env.workspaceDirectoryParentEnabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup)
    )
      return plan;
    const execution = env.workspaceDirectoryGoogleGroupCleanupDisabled
      ? "disabled"
      : env.workspaceDirectoryGoogleGroupCleanupMode === "live"
        ? "managed"
        : "audit-only";
    const branch = await cleanupAdapter.capture(plan, execution, reviewed);
    return parseWorkspaceDirectoryPlan({
      ...plan,
      branches: [...plan.branches, branch],
    });
  }
  async function appendPagerDutyBranch(
    plan: WorkspaceDirectoryPlan,
    includes: (actionId: WorkspaceDirectoryAuthorizedActionId) => boolean,
  ): Promise<WorkspaceDirectoryPlan> {
    if (
      !env.workspaceDirectoryParentEnabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams) ||
      (options.pagerDutyTeamService === undefined &&
        bindings.pagerDutyPolicy.mappings.length === 0)
    )
      return plan;
    const branch = await pagerDutyAdapter.capture(
      plan,
      env.pagerdutyTeamSyncDisabled ? "disabled" : "managed",
    );
    return parseWorkspaceDirectoryPlan({
      ...plan,
      branches: [...plan.branches, branch],
    });
  }
  async function appendSentryBranch(
    plan: WorkspaceDirectoryPlan,
    includes: (actionId: WorkspaceDirectoryAuthorizedActionId) => boolean,
  ): Promise<WorkspaceDirectoryPlan> {
    if (
      !env.workspaceDirectoryParentEnabled ||
      !includes(WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships)
    ) {
      return plan;
    }
    const branch = await sentryAdapter.capture(
      plan,
      sentryWorkspaceParentConfig({
        enabled: env.workspaceDirectorySentryEnabled,
        rawAuthorityPins: env.workspaceDirectorySentryAuthorityPins,
      }),
    );
    return parseWorkspaceDirectoryPlan({
      ...plan,
      branches: [...plan.branches, branch],
    });
  }
  const cleanupAdapter = new ReviewedGoogleGroupCleanupAdapter({
    service: cleanupService,
    assertGoogleAuthority,
    ...(options.googleGroupCleanupParentContext !== undefined && {
      parentContext: options.googleGroupCleanupParentContext,
    }),
  });
  const pagerDutyAdapter = new ReviewedPagerDutyTeamAdapter({
    service: pagerDutyService,
    assertGoogleAuthority,
    ...(options.pagerDutyTeamParentContext !== undefined && {
      parentContext: options.pagerDutyTeamParentContext,
    }),
  });
  const sentryAdapter = new ReviewedSentryWorkspaceAdapter({
    service: sentryService,
    assertGoogleAuthority,
    ...(options.sentryParentContext !== undefined && {
      parentContext: options.sentryParentContext,
    }),
  });
  const nameAdapter = new ReviewedWorkspaceNameAdapter({
    services: nameServices,
    assertGoogleAuthority,
    ...(options.nameRepairParentContext !== undefined && {
      parentContext: options.nameRepairParentContext,
    }),
  });
  return {
    applyGoogleGroupCleanup: (plan) => cleanupAdapter.apply(plan),
    applyPagerDutyTeams: (plan) => pagerDutyAdapter.apply(plan),
    applySentryMemberships: (plan) => sentryAdapter.apply(plan),
    readPagerDutyTeamsSlice: (plan) => pagerDutyAdapter.readSlice(plan),
    readSentryMembershipsSlice: (plan) => sentryAdapter.readSlice(plan),
    readGoogleGroupCleanupSlice: (plan) => cleanupAdapter.readSlice(plan),
    applyNameRepair: (plan, branchId) => nameAdapter.apply(plan, branchId),
    readNameRepairSlice: (plan, branchId) =>
      nameAdapter.readSlice(plan, branchId),
    readNameSourceFingerprint: (branchId) =>
      namesEnabled()
        ? nameAdapter.readSourceFingerprint(branchId)
        : Promise.resolve(null),
    async applyAccessGuard(plan) {
      const accessGuard = plan.branches[4];
      if (accessGuard.execution !== "managed") {
        return "Access Guard is disabled; no Linear mutation was attempted.";
      }
      if (
        accessGuard.scheduledLinearSuspension === true &&
        (!env.workspaceDirectoryParentEnabled ||
          !env.workspaceDirectoryLinearSuspensionsEnabled)
      )
        throw new Error("workspace_scheduled_linear_suspension_disabled");
      await assertGoogleAuthority(plan);
      assertRequiredIdentityBudget(
        env.workspaceDirectoryParentEnabled,
        options.linearIdentityBudget,
        "linear",
      );
      const parentContext = env.workspaceDirectoryParentEnabled
        ? options.linearSuspensionParentContext?.(plan)
        : undefined;
      const converged = await bindings.accessGuard().service.applyLinearPlan(
        accessGuard.plan,
        options.linearIdentityBudget,
        bindWorkspaceLinearParentContext(parentContext, () =>
          assertGoogleAuthority(plan),
        ),
      );
      return `${String(converged)} Linear account suspensions converged.`;
    },
    async applyDriveOrgChart(plan) {
      const branch = plan.branches[1];
      if (branch.execution !== "managed") {
        return "Organization chart is disabled; no mutation was attempted.";
      }
      assertDriveOrgChartFileId(
        branch,
        getWorkspaceSyncPolicy().org.orgChartFileId,
        env.workspaceDirectoryParentEnabled,
      );
      assertSha256(
        branch.desiredSha256,
        "workspace_directory_org_chart_desired_hash_invalid",
      );
      const users = await assertGoogleAuthority(plan);
      assertSha256(
        branch.currentSha256,
        "workspace_directory_org_chart_current_hash_invalid",
      );
      const report = await bindings
        .org(options.channelLeaseRepository)
        .chart.run({
          expectedCurrentSha256: branch.currentSha256,
          expectedFileId: branch.fileId,
          expectedSha256: branch.desiredSha256,
          mode: "live",
          users,
        });
      if (
        report.sha256 !== branch.desiredSha256 ||
        report.currentSha256 !== branch.desiredSha256
      ) {
        throw new Error("workspace_directory_org_chart_readback_mismatch");
      }
      assertDriveOrgChartFileId(
        branch,
        report.fileId,
        env.workspaceDirectoryParentEnabled,
      );
      return `Organization chart ${report.drive?.action ?? "unchanged"} and content hash verified.`;
    },
    async applyGitHubAccess(plan, githubDispatchClaim) {
      const branch = plan.branches[3];
      if (branch.execution !== "managed") {
        return "GitHub organization access is audit-only; no mutation was attempted.";
      }
      const users = await assertGoogleAuthority(plan);
      assertRequiredIdentityBudget(
        env.workspaceDirectoryParentEnabled,
        options.githubIdentityBudget,
        "github",
      );
      const fresh = await captureManagedGithubState(bindings, env, users);
      if (
        fresh.branch.contentHash !== branch.contentHash ||
        !sameManagedGitHubSelection(
          fresh.branch.selectedOperation,
          branch.selectedOperation,
        )
      ) {
        throw new Error("workspace_directory_github_access_plan_drift");
      }
      const context = env.workspaceDirectoryParentEnabled
        ? options.githubParentContext?.(plan)
        : undefined;
      if (githubDispatchClaim !== undefined && context === undefined)
        throw new Error("github_original_parent_context_required");
      return applyManagedGitHubAccess(
        branch,
        createManagedGithubPort(bindings, env, branch),
        fresh.selectedDesired,
        (googleUserId) =>
          refreshManagedGitHubDesiredAuthority(
            branch,
            googleUserId,
            () => assertGoogleAuthority(plan),
            (latestUsers) =>
              captureManagedGithubState(bindings, env, latestUsers),
            () => captureManagedGithubSource(bindings),
          ),
        options.githubIdentityBudget,
        context === undefined
          ? undefined
          : { ...context, ...(githubDispatchClaim && { githubDispatchClaim }) },
      );
    },
    applyIdentityProvisioning: (plan) => {
      assertRequiredIdentityBudget(
        env.workspaceDirectoryParentEnabled,
        options.googleIdentityBudget,
        "google",
      );
      return applyWorkspaceDirectoryIdentityProvisioning(plan, {
        assertGoogleAuthority,
        identityBudget: options.googleIdentityBudget,
        identitySchema,
        identitySeed,
        parentOwned: env.workspaceDirectoryParentEnabled,
      });
    },
    async applySlackGroupsChannels(plan) {
      const branch = plan.branches[2];
      if (branch.execution !== "managed") {
        return "Slack groups and channels are audit-only; no mutation was attempted.";
      }
      assertRequiredIdentityBudget(
        env.workspaceDirectoryParentEnabled,
        options.slackIdentityBudget,
        "slack",
      );
      assertSha256(branch.planHash, SLACK_CHANNEL_PLAN_HASH_INVALID);
      if (!options.channelLeaseRepository) {
        throw new Error(
          "workspace_directory_slack_channel_runtime_unavailable",
        );
      }
      if (!options.channelDatabase) {
        throw new Error(
          "workspace_directory_slack_channel_provenance_runtime_unavailable",
        );
      }
      if (env.orgChannelSyncMode !== "live") {
        throw new Error(
          "workspace_directory_slack_channel_kill_switch_engaged",
        );
      }
      const googleUsers = await assertGoogleAuthority(plan);
      const runtime = bindings.channels({
        database: options.channelDatabase,
        kind: "scheduled",
        leaseRepository: options.channelLeaseRepository,
      });
      await assertSlackMembershipIdentity(branch, runtime.service, googleUsers);
      const result = await runtime.service.run({
        ...reviewedSlackLifecycleOptions(plan),
        allowRemovals: runtime.allowRemovals,
        requireUnprivilegedIdentity:
          branch.selectedIdentity !== undefined &&
          hasSelectedSlackMembershipRemoval(branch) &&
          !isExactContractorAdministratorRemoval(branch),
        expectedPlanHash: branch.planHash,
        googleUsers,
        identityBudget:
          branch.selectedIdentity === undefined
            ? options.slackIdentityBudget
            : {
                required: true,
                reserve: async (googleUserId) => {
                  if (googleUserId !== branch.selectedIdentity?.googleUserId)
                    throw new Error(SLACK_MEMBERSHIP_IDENTITY_CHANGED);
                  await reserveIdentityWriteBudget(
                    options.slackIdentityBudget,
                    googleUserId,
                  );
                },
              },
        mode: "live",
        trigger: "cron",
      });
      if (result.status !== "success") {
        throw new Error(slackChannelRunError(result));
      }
      if (result.planHash !== branch.planHash) {
        throw new Error(
          "workspace_directory_slack_channel_plan_readback_mismatch",
        );
      }
      return `${String(result.writes)} Slack group or channel changes converged and were verified.`;
    },
    async applySlackProfiles(plan) {
      const branch = plan.branches[0];
      if (branch.execution !== "managed") {
        return "Slack profiles are audit-only; no mutation was attempted.";
      }
      assertRequiredIdentityBudget(
        env.workspaceDirectoryParentEnabled,
        options.slackIdentityBudget,
        "slack",
      );
      assertSha256(branch.planHash, SLACK_PROFILE_PLAN_HASH_INVALID);
      if (env.orgSyncMode !== "live") {
        throw new Error(
          "workspace_directory_slack_profile_kill_switch_engaged",
        );
      }
      if (
        branch.diagnostics.some(
          ({ code }) => code === "profile_plan_role_blocked",
        )
      ) {
        throw new Error("workspace_directory_slack_profile_role_blocked");
      }
      const googleUsers = await assertGoogleAuthority(plan);
      const runtime = bindings.org();
      const preflight = await runtime.service.run(
        { mode: "audit", trigger: "cron" },
        googleUsers,
      );
      if (preflight.planHash !== branch.planHash) {
        throw new Error("workspace_directory_slack_profile_authority_drifted");
      }
      if (preflight.blocked.length > 0) {
        throw new Error("workspace_directory_slack_profile_role_blocked");
      }
      const result = await runtime.service.run(
        {
          expectedPlanHash: branch.planHash,
          identityBudget: options.slackIdentityBudget,
          mode: "live",
          trigger: "cron",
        },
        googleUsers,
      );
      if (result.planHash !== branch.planHash || result.status !== "success") {
        throw new Error(`workspace_directory_slack_profile_${result.status}`);
      }
      return `${String(result.writes)} Slack profile changes converged and were verified.`;
    },
    capture,
    identityTransitionsExcluded:
      !env.workspaceDirectoryGithubIdentitySeedEnabled,
    async applyTrycomp(plan) {
      const branch = plan.branches.find(
        (candidate) => candidate.branchId === "trycomp-people",
      );
      if (branch?.execution !== "managed")
        throw new Error("workspace_trycomp_branch_not_managed");
      await assertGoogleAuthority(plan);
      return trycomp.apply(branch.reviewedPlan);
    },
    async readTrycompSlice(plan) {
      const branch = plan.branches.find(
        (candidate) => candidate.branchId === "trycomp-people",
      );
      if (branch?.reviewedPlan === null || branch === undefined) {
        throw new Error("workspace_trycomp_reviewed_plan_missing");
      }
      return JsonValueSchema.parse(
        await trycomp.readSlice(branch.reviewedPlan),
      );
    },
    readTrycompSourceFingerprint: () => trycomp.sourceFingerprint(),
    async readAccessGuardLinearSlice(actions) {
      return JsonValueSchema.parse(
        await bindings.accessGuard().service.readLinearManagedSlice(actions),
      );
    },
    async readAuthorityFingerprint() {
      return fingerprintGoogleAuthority(await captureGoogle());
    },
    async readDriveOrgChartSlice(plan) {
      const branch = plan.branches[1];
      if (branch.execution !== "managed") return JsonValueSchema.parse(null);
      assertDriveOrgChartFileId(
        branch,
        getWorkspaceSyncPolicy().org.orgChartFileId,
        env.workspaceDirectoryParentEnabled,
      );
      const users = await captureGoogle();
      const report = await bindings.org().chart.run({ mode: "audit", users });
      assertDriveOrgChartFileId(
        branch,
        report.fileId,
        env.workspaceDirectoryParentEnabled,
      );
      return driveOrgChartManagedSlice(branch, report.currentSha256);
    },
    async readGitHubAccessSlice(plan) {
      const branch = plan.branches[3];
      if (branch.execution !== "managed") return JsonValueSchema.parse([]);
      const fresh = await captureManagedGithubState(
        bindings,
        env,
        await captureGoogle(),
      );
      return readManagedGitHubTargetSlice(
        branch,
        createManagedGithubPort(bindings, env, branch),
        fresh.desiredByUserId,
      );
    },
    async readGitHubAccessAuthorityFingerprint() {
      if (
        env.githubAccessAuditDisabled ||
        env.githubOrganizationSyncDisabled ||
        env.githubOrganizationSyncMaxChanges === 0
      ) {
        return null;
      }
      if (env.githubOrganizationSyncMaxChanges !== 1) {
        throw new Error(GITHUB_ACCESS_KILL_SWITCH_ENGAGED);
      }
      await assertManagedGithubCredentials(env);
      const users = await captureGoogle();
      const source = await captureManagedGithubSource(bindings);
      return captureManagedGitHubAuthorityFingerprint(
        users,
        source.google,
        {
          maxChanges: env.githubOrganizationSyncMaxChanges,
          organizationId: env.githubOrganizationSyncOrganizationId,
          organizationLogin: env.githubOrganizationSyncOrganizationLogin,
          rootGroupEmail: source.rootGroupEmail,
          token: env.githubOrganizationSyncToken,
        },
        source.policy,
      );
    },
    async readIdentitySchemaSlice() {
      return JsonValueSchema.parse(await identitySchema.readManagedSlice());
    },
    async readGithubIdentitySeedSlice(plan) {
      const seedPlan = plan.branches[5].githubIdentitySeed;
      if (seedPlan.kind !== "managed") return JsonValueSchema.parse([]);
      if (!identitySeed)
        throw new Error(GOOGLE_GITHUB_IDENTITY_SEED_RUNTIME_UNAVAILABLE);
      return JsonValueSchema.parse(
        await identitySeed.readManagedSlice(seedPlan),
      );
    },
    async readGithubIdentitySourceFingerprint() {
      if (!identitySeed) return null;
      return fingerprintGithubIdentitySource(
        await identitySeed.captureSource(),
      );
    },
    async readSlackGroupsChannelsObservationSlice(plan) {
      const users = await captureGoogle();
      const channelRuntime = bindings.channels({
        ...(options.channelDatabase && { database: options.channelDatabase }),
        kind: "audit",
      });
      return readOriginalSlackMembershipObservation(
        env,
        users,
        plan.branches[2],
        channelRuntime,
      );
    },
    async readSlackGroupsChannelsSlice(plan) {
      const planned = plan.branches[2];
      if (planned.execution !== "managed") {
        return slackGroupsChannelsAfterSlice(planned);
      }
      assertSha256(planned.planHash, SLACK_CHANNEL_PLAN_HASH_INVALID);
      const users = await captureGoogle();
      const channelRuntime = bindings.channels({
        ...(options.channelDatabase && { database: options.channelDatabase }),
        kind: "audit",
      });
      const fresh = SlackGroupsChannelsBranchPlanSchema.parse(
        await captureChannels(
          bindings,
          env,
          users,
          options.channelDatabase,
          channelRuntime,
          {
            kind: "original-target-readback",
            branch: planned,
          },
        ),
      );
      if (fresh.execution !== "managed" || isKillSwitchEngaged(fresh)) {
        return JsonValueSchema.parse({ state: "kill-switch-engaged" });
      }
      if (fresh.diagnostics.some(({ severity }) => severity === "blocker")) {
        return JsonValueSchema.parse({
          planHash: fresh.planHash,
          state: "drifted",
        });
      }
      if (fresh.planHash === planned.planHash)
        return slackGroupsChannelsBeforeSlice(planned);
      const selectedGroupsConverged = slackSelectedUserGroupsConverged(
        planned,
        fresh,
      );
      const selectedRenameConverged = await exactChannelRenameConverged(
        planned,
        channelRuntime.service,
      );
      const selectedProvenanceRemovalsConverged =
        await exactChannelRemovalsConverged(
          planned,
          fresh,
          channelRuntime.service,
        );
      return [
        selectedGroupsConverged,
        selectedRenameConverged,
        selectedProvenanceRemovalsConverged,
      ].every(Boolean)
        ? slackGroupsChannelsAfterSlice(planned)
        : JsonValueSchema.parse({ planHash: fresh.planHash, state: "drifted" });
    },
    async readSlackProfilesSlice(plan) {
      const planned = plan.branches[0];
      if (planned.execution !== "managed")
        return slackProfilesAfterSlice(planned);
      assertSha256(planned.planHash, SLACK_PROFILE_PLAN_HASH_INVALID);
      const googleUsers = await captureGoogle();
      const fresh = await bindings
        .org()
        .service.run({ mode: "audit", trigger: "http" }, googleUsers);
      if (fresh.status !== "audit")
        return JsonValueSchema.parse({ state: "unavailable" });
      const freshBySlackId = new Map(
        fresh.planned.map((profile) => [profile.slackUserId, profile]),
      );
      const unchanged = planned.changes.every((change) => {
        const observed = freshBySlackId.get(change.slackUserId);
        return (
          observed !== undefined &&
          sameManagedFields(observed.current, change.before)
        );
      });
      if (fresh.planHash === planned.planHash && unchanged) {
        return slackProfilesBeforeSlice(planned);
      }
      const converged = planned.changes.every((change) => {
        const observed = freshBySlackId.get(change.slackUserId);
        return (
          observed !== undefined &&
          sameManagedFields(observed.current, change.after)
        );
      });
      return converged
        ? slackProfilesAfterSlice(planned)
        : JsonValueSchema.parse({ planHash: fresh.planHash, state: "drifted" });
    },
  };
  function reviewedSlackLifecycleOptions(plan: WorkspaceDirectoryPlan) {
    const branch = plan.branches[2];
    if (
      branch.execution !== "managed" ||
      branch.reviewedLifecycleRemoval === undefined
    )
      return {};
    assertReviewedLifecycleParentEnabled(env, branch.reviewedLifecycleRemoval);
    const parent = options.reviewedSlackLifecycleParentContext?.(plan);
    if (parent === undefined)
      throw new Error("reviewed_lifecycle_signed_parent_required");
    const reviewedLifecycleParent: ReviewedSlackLifecycleParentContext = {
      assertFreshPlan: () => parent.assertFreshPlan(),
      assertWriteAuthority: async (group) => {
        await parent.assertWriteAuthority(group);
        await assertGoogleAuthority(plan);
        parent.assertFreshPlan();
      },
      assertFinalGoogleAuthority: async (users) => {
        if (
          (await fingerprintGoogleAuthority(users)) !==
          plan.authorityFingerprint
        )
          throw new Error("google_authority_drift");
        parent.assertFreshPlan();
      },
    };
    return {
      reviewedLifecycleRemoval: branch.reviewedLifecycleRemoval,
      reviewedLifecycleParent,
    };
  }
}
export function isExactContractorAdministratorRemoval(
  branch: WorkspaceDirectoryPlan["branches"][2],
): boolean {
  if (branch.execution !== "managed" || branch.selectedIdentity === undefined)
    return false;
  const group = branch.selectedUserGroups[0];
  const removal = group?.memberRemovals[0];
  return (
    branch.additions.length === 0 &&
    branch.removals.length === 0 &&
    branch.channelRenames.length === 0 &&
    branch.selectedChannelRename === null &&
    branch.selectedProvenanceChannelRemovals.length === 0 &&
    branch.selectedRemovalCount === 1 &&
    branch.selectedUserGroupHandles.length === 1 &&
    branch.selectedUserGroupHandles[0] === "group-contractors" &&
    branch.selectedUserGroups.length === 1 &&
    group?.handle === "group-contractors" &&
    group.authority.kind === "google_group" &&
    group.authority.email ===
      getWorkspaceSyncPolicy().contractorAuthorityGroup.email &&
    group.authority.id ===
      getWorkspaceSyncPolicy().contractorAuthorityGroup.id &&
    group.automationOwnership.kind !== "legacy_unmanaged" &&
    group.automationOwnership.sourceGoogleGroupIds.length === 1 &&
    group.automationOwnership.sourceGoogleGroupIds[0] ===
      getWorkspaceSyncPolicy().contractorAuthorityGroup.id &&
    group.memberRemovalAuthority === "contractor_group_authoritative" &&
    group.memberAdditions.length === 0 &&
    group.channelAdditions.length === 0 &&
    group.channelRemovals.length === 0 &&
    group.effectiveAccessAdditions.length === 0 &&
    group.memberRemovals.length === 1 &&
    removal?.slackUserId === branch.selectedIdentity.slackUserId
  );
}
export function hasSelectedSlackMembershipRemoval(
  branch: WorkspaceDirectoryPlan["branches"][2],
): boolean {
  if (branch.execution !== "managed") return false;
  return (
    branch.selectedProvenanceChannelRemovals.length > 0 ||
    branch.selectedUserGroups.some((group) => group.memberRemovals.length > 0)
  );
}
function assertReviewedLifecycleParentEnabled(
  env: ValidatedEnv,
  reviewed?: ReviewedLinearSuspension | ReviewedSlackLifecycleRemoval,
) {
  if (reviewed !== undefined && !env.workspaceDirectoryParentEnabled)
    throw new Error("workspace_reviewed_lifecycle_parent_disabled");
}
export function disabledSlackGroupsChannelsPlan(
  reason = "org_channel_sync_disabled",
): WorkspaceDirectoryPlan["branches"][2] {
  return {
    additions: [],
    branchId: "slack-groups-channels",
    channelRenames: [],
    diagnostics: [disabledDiagnostic(reason)],
    execution: "disabled",
    killSwitchEngaged: true,
    lifecycle: {
      googleTeamGroupsOutsideAssignmentAllowlist: [],
      nonstandardPublicChannels: [],
      privateChannelRenameCandidates: [],
      slackTeamChannelCollisions: [],
      slackUsersWithoutTeamAssignment: [],
      verticalRetirementCandidates: [],
    },
    planHash: null,
    removals: [],
    selectedChannelAdditions: [],
    selectedChannelRename: null,
    selectedProvenanceChannelRemovals: [],
    selectedRemovalCount: 0,
    selectedUserGroupHandles: [],
    selectedUserGroups: [],
    userGroups: [],
  };
}
type SlackGroupsChannelsPlan = WorkspaceDirectoryPlan["branches"][2];
type ManagedSlackGroupsChannelsPlan = Extract<
  SlackGroupsChannelsPlan,
  {
    execution: "managed";
  }
>;
type SelectedSlackUserGroupReview =
  ManagedSlackGroupsChannelsPlan["selectedUserGroups"][number];
type SlackUserGroupPlan = ManagedSlackGroupsChannelsPlan["userGroups"][number];
export function slackSelectedUserGroupsConverged(
  planned: SlackGroupsChannelsPlan,
  fresh: SlackGroupsChannelsPlan,
): boolean {
  if (
    planned.execution !== "managed" ||
    fresh.execution !== "managed" ||
    fresh.diagnostics.some(({ severity }) => severity === "blocker")
  )
    return false;
  return planned.selectedUserGroupHandles.every((handle) => {
    const review = planned.selectedUserGroups.find(
      (group) => group.handle === handle,
    );
    const plannedGroup = planned.userGroups.find(
      (group) => group.handle === handle,
    );
    const current = fresh.userGroups.find((group) => group.handle === handle);
    if (!review || !plannedGroup || !current) return false;
    return slackSelectedUserGroupConverged(review, plannedGroup, current);
  });
}
function slackSelectedUserGroupConverged(
  review: SelectedSlackUserGroupReview,
  planned: SlackUserGroupPlan,
  current: SlackUserGroupPlan,
): boolean {
  if (review.automationOwnership.kind === "legacy_unmanaged") return false;
  const exactReviewedState =
    sameStringMultiset(
      review.requiredChannelIds,
      review.automationOwnership.allowedChannelIds,
    ) &&
    current.currentHandle === review.handle &&
    current.currentName === review.desiredName &&
    current.desiredName === review.desiredName &&
    dequal(current.automationOwnership, review.automationOwnership) &&
    dequal(current.authority, review.authority) &&
    sameStringMultiset(
      current.requiredChannelIds ?? [],
      review.requiredChannelIds,
    ) &&
    sameStringMultiset(current.desiredChannelIds, planned.desiredChannelIds) &&
    sameStringMultiset(current.desiredUserIds, planned.desiredUserIds) &&
    (review.automationOwnership.kind === "automation_bootstrap" ||
      selectedSlackUserGroupTargetMatches(review, planned, current));
  if (!exactReviewedState) return false;
  if (review.automationOwnership.kind === "automation_bootstrap") {
    return (
      current.slackUserGroupId !== null &&
      sameStringMultiset(
        current.memberAdditionUserIds ?? [],
        current.desiredUserIds,
      )
    );
  }
  return (
    review.expectedSlackUserGroupId !== null &&
    review.slackUserGroupId === review.expectedSlackUserGroupId &&
    current.slackUserGroupId === review.expectedSlackUserGroupId &&
    (current.status === "in_sync" || current.status === "update")
  );
}
function selectedSlackUserGroupTargetMatches(
  review: SelectedSlackUserGroupReview,
  planned: SlackUserGroupPlan,
  current: SlackUserGroupPlan,
): boolean {
  const expectedChannelIds = applySlackSelection(
    observedSlackIds(
      planned.desiredChannelIds,
      planned.channelAdditionIds ?? [],
      planned.channelRemovalIds ?? [],
    ),
    review.channelAdditionIds,
    review.channelRemovalIds,
  );
  const expectedUserIds = applySlackSelection(
    observedSlackIds(
      planned.desiredUserIds,
      planned.memberAdditionUserIds ?? [],
      planned.memberRemovalUserIds ?? [],
    ),
    review.memberAdditions.map(({ slackUserId }) => slackUserId),
    review.memberRemovals.map(({ slackUserId }) => slackUserId),
  );
  const observedChannelIds = observedSlackIds(
    current.desiredChannelIds,
    current.channelAdditionIds ?? [],
    current.channelRemovalIds ?? [],
  );
  const observedUserIds = observedSlackIds(
    current.desiredUserIds,
    current.memberAdditionUserIds ?? [],
    current.memberRemovalUserIds ?? [],
  );
  return (
    sameStringMultiset(observedChannelIds, expectedChannelIds) &&
    sameStringMultiset(observedUserIds, expectedUserIds)
  );
}
function observedSlackIds(
  desiredIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- All sets contain the same Slack user-ID role.
  pendingAdditionIds: readonly string[],
  pendingRemovalIds: readonly string[],
): string[] {
  const additions = new Set(pendingAdditionIds);
  const observed = new Set(desiredIds.filter((id) => !additions.has(id)));
  for (const id of pendingRemovalIds) observed.add(id);
  return [...observed].toSorted((left, right) => left.localeCompare(right));
}
function applySlackSelection(
  currentIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- All sets contain the same Slack user-ID role.
  additionIds: readonly string[],
  removalIds: readonly string[],
): string[] {
  const selected = new Set(currentIds);
  for (const id of removalIds) selected.delete(id);
  for (const id of additionIds) selected.add(id);
  return [...selected].toSorted((left, right) => left.localeCompare(right));
}
const SLACK_MEMBERSHIP_IDENTITY_CHANGED =
  "workspace_slack_membership_identity_changed";
export async function assertSlackMembershipIdentity(
  branch: SlackGroupsChannelsPlan,
  service: Pick<OrgChannelSyncService, "readMembershipIdentities">,
  users: readonly GoogleDirectoryUser[],
): Promise<void> {
  if (branch.execution !== "managed" || branch.selectedIdentity === undefined)
    return;
  const pin = branch.selectedIdentity;
  const identities = await service.readMembershipIdentities(
    [pin.slackUserId],
    users,
  );
  if (
    selectedSlackMembershipUserId(branch) !== pin.slackUserId ||
    identities.get(pin.slackUserId) !== pin.googleUserId
  )
    throw new Error(SLACK_MEMBERSHIP_IDENTITY_CHANGED);
}
type SlackProfilesPlan = WorkspaceDirectoryPlan["branches"][0];
function sameManagedFields(
  left: SlackProfilesPlan["changes"][number]["before"],
  right: SlackProfilesPlan["changes"][number]["after"],
): boolean {
  return dequal(left, right);
}
function parseWorkspaceDirectoryPlan(input: unknown): WorkspaceDirectoryPlan {
  const parsed = WorkspaceDirectoryPlanSchema.safeParse(input);
  if (parsed.success) return parsed.data;
  const issues = workspaceDirectoryContractIssuePaths(parsed.error);
  logErrorEvent("workspace_directory.plan_contract_invalid", {
    "issue_count": parsed.error.issues.length,
    "issue_paths": issues.join(","),
  });
  throw contractError("workspace-directory.plan", parsed.error);
}
export function workspaceDirectoryContractIssuePaths(
  error: z.ZodError,
): string[] {
  return error.issues
    .slice(0, 20)
    .map((issue) => `${issue.path.map(String).join(".")}:${issue.code}`)
    .toSorted((left, right) => left.localeCompare(right));
}
export async function captureWorkspaceDirectoryIdentitySchema(
  selected: boolean,
  identitySchema: Pick<SarjIdentitySchemaService, "plan">,
  parentOwned = false,
): Promise<WorkspaceDirectoryPlan["branches"][5]["schemaPlan"]> {
  if (parentOwned || !selected) return { kind: "not-selected" };
  return captureWorkspaceDirectoryComponent(
    "workspace-directory.google-identity-schema",
    () => identitySchema.plan(),
  );
}
interface WorkspaceDirectoryFanoutResult<A, B, C, D, E, F, G> {
  access: E;
  channels: C;
  chart: B;
  github: D;
  identitySeed: G;
  profiles: A;
  schema: F;
}
export async function captureWorkspaceDirectoryFanout<
  A,
  B,
  C,
  D,
  E,
  F,
  G,
>(captures: {
  access: () => Promise<E>;
  channels: () => Promise<C>;
  chart: () => Promise<B>;
  github: () => Promise<D>;
  identitySeed: () => Promise<G>;
  profiles: () => Promise<A>;
  schema: () => Promise<F>;
}): Promise<WorkspaceDirectoryFanoutResult<A, B, C, D, E, F, G>> {
  const chart = await captures.chart();
  const [profiles, channels] = await Promise.all([
    captures.profiles(),
    captures.channels(),
  ]);
  const access = await captures.access();
  const [identitySeed, schema] = await Promise.all([
    captures.identitySeed(),
    captures.schema(),
  ]);
  const github = await captures.github();
  return { access, channels, chart, github, identitySeed, profiles, schema };
}
export async function captureWorkspaceDirectoryComponent<T>(
  component: string,
  capture: () => Promise<T>,
): Promise<T> {
  try {
    return await capture();
  } catch (error) {
    if (
      error instanceof OperationContractError ||
      error instanceof OperationSourceError
    )
      throw error;
    if (error instanceof z.ZodError) throw contractError(component, error);
    throw new OperationSourceError(component, { cause: error });
  }
}
function captureComponentSync<T>(component: string, capture: () => T): T {
  try {
    return capture();
  } catch (error) {
    if (error instanceof OperationContractError) throw error;
    if (error instanceof z.ZodError) throw contractError(component, error);
    throw error;
  }
}
function contractError(
  component: string,
  error: z.ZodError,
): OperationContractError {
  return new OperationContractError(component, { cause: error });
}
async function captureDriveOrgChart(
  bindings: WorkspaceSyncRuntimeBindings,
  users: GoogleDirectoryUser[],
) {
  const runtime = bindings.org();
  const chart = await runtime.chart.run({ mode: "audit", users });
  return {
    branchId: "drive-org-chart" as const,
    bytes: chart.bytes,
    currentSha256: chart.currentSha256,
    desiredSha256: chart.sha256,
    fileId: chart.fileId,
    diagnostics: [
      {
        code: "managed_exact_content_hash",
        message:
          "Drive content is compared before write and verified by exact SHA-256 readback.",
        severity: "info" as const,
      },
    ],
    execution: "managed" as const,
    killSwitchEngaged: false,
    people: chart.people,
    photos: chart.photos,
  };
}
async function captureProfiles(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  users: GoogleDirectoryUser[],
) {
  const profiles = await bindings
    .org()
    .service.run({ mode: "audit", trigger: "http" }, users);
  return profileBranchFromAudit(profiles, env.orgSyncMode === "live");
}
export function profileBranchFromAudit(
  profiles: Pick<
    OrgSyncRunReport,
    | "blocked"
    | "errors"
    | "planHash"
    | "planned"
    | "selectedSlackUserId"
    | "status"
    | "warnings"
  >,
  managed: boolean,
) {
  if (profiles.status === "failed") {
    throw new OperationSourceError("workspace-directory.slack-profiles");
  }
  return {
    branchId: "slack-profiles" as const,
    changes: profiles.planned
      .filter(
        (profile) =>
          profile.changedFields.length > 0 &&
          profile.slackUserId === profiles.selectedSlackUserId,
      )
      .map((profile) => ({
        after: profile.desired,
        before: profile.current,
        changedFields: profile.changedFields,
        googleUserId: profile.googleUserId,
        identity: profile.identity,
        reason: profile.reason,
        slackUserId: profile.slackUserId,
      })),
    diagnostics: projectProfilePlanDiagnostics(profiles, managed),
    ...(managed
      ? { execution: "managed" as const, killSwitchEngaged: false as const }
      : { execution: "audit-only" as const, killSwitchEngaged: true as const }),
    planHash: profiles.planHash,
  };
}
function disabledDriveOrgChartPlan(reason = "org_sync_disabled") {
  return {
    branchId: "drive-org-chart" as const,
    bytes: 0,
    currentSha256: null,
    desiredSha256: null,
    diagnostics: [disabledDiagnostic(reason)],
    execution: "disabled" as const,
    killSwitchEngaged: true,
    people: 0,
    photos: 0,
  };
}
function disabledSlackProfilesPlan(reason = "org_sync_disabled"): Extract<
  WorkspaceDirectoryPlan["branches"][0],
  {
    execution: "disabled";
  }
> {
  return {
    branchId: "slack-profiles" as const,
    changes: [],
    diagnostics: [disabledDiagnostic(reason)],
    execution: "disabled" as const,
    killSwitchEngaged: true,
    planHash: null,
  };
}
export function projectProfilePlanDiagnostics(
  profiles: Pick<OrgSyncRunReport, "blocked" | "errors" | "warnings">,
  managed = false,
) {
  return [
    ...profiles.blocked.map(({ error }) => ({
      code: managed
        ? "profile_plan_role_blocked"
        : "profile_plan_role_audit_only",
      message: error,
      ...(managed
        ? {
            scope: {
              actionId: "workspace-directory.slack-profiles" as const,
              kind: "action" as const,
            },
            severity: "blocker" as const,
          }
        : { severity: "warning" as const }),
    })),
    ...profiles.errors.map((message) => ({
      code: "profile_plan_error",
      message,
      scope: { kind: "audit" as const, provider: "slack" as const },
      severity: "blocker" as const,
    })),
    ...profiles.warnings.map((message) => ({
      code: "profile_plan_warning",
      message,
      severity: "warning" as const,
    })),
  ];
}
type SlackChannelTargetReader = Pick<
  OrgChannelSyncService,
  "readChannelIdentity" | "readChannelMemberIds"
>;
export async function exactChannelRenameConverged(
  planned: WorkspaceDirectoryPlan["branches"][2],
  reader: SlackChannelTargetReader,
): Promise<boolean> {
  const rename = planned.selectedChannelRename;
  if (!rename) return true;
  const identity = await reader.readChannelIdentity(rename.channelId);
  return (
    identity.id === rename.channelId &&
    !identity.isArchived &&
    identity.isPrivate === rename.isPrivate &&
    identity.name === rename.expectedName
  );
}
export async function exactChannelRemovalsConverged(
  planned: WorkspaceDirectoryPlan["branches"][2],
  fresh: WorkspaceDirectoryPlan["branches"][2],
  reader: SlackChannelTargetReader,
): Promise<boolean> {
  for (const selected of planned.selectedProvenanceChannelRemovals) {
    if (
      fresh.additions.some(
        (addition) =>
          addition.channelId === selected.channelId &&
          addition.slackUserId === selected.slackUserId,
      )
    )
      return false;
    // eslint-disable-next-line no-await-in-loop -- every exact reviewed edge needs provider readback.
    const members = await reader.readChannelMemberIds(selected.channelId);
    if (members.includes(selected.slackUserId)) return false;
  }
  return true;
}
type ChannelCapturePurpose =
  | {
      kind: "new-plan";
    }
  | {
      kind: "original-target-readback";
      branch: SlackGroupsChannelsPlan;
    };
interface ChannelCaptureRuntime {
  allowRemovals: boolean;
  service: Pick<
    OrgChannelSyncService,
    "readMembershipIdentities" | "readMembershipPlan" | "run"
  >;
}
const NEW_PLAN_CAPTURE_PURPOSE = {
  kind: "new-plan",
} as const satisfies ChannelCapturePurpose;
export async function captureChannels(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  googleUsers: readonly GoogleDirectoryUser[],
  database?: D1Database,
  existingRuntime?: ChannelCaptureRuntime,
  purpose: ChannelCapturePurpose = NEW_PLAN_CAPTURE_PURPOSE,
  reviewedLifecycleRemoval?: ReviewedSlackLifecycleRemoval,
) {
  const runtime =
    existingRuntime ??
    bindings.channels({
      ...(database && { database }),
      kind: "audit",
    });
  const report = await captureChannelReport(
    runtime,
    googleUsers,
    purpose,
    reviewedLifecycleRemoval,
  );
  const branch = SlackGroupsChannelsBranchPlanSchema.parse({
    ...reviewedLifecycleBranchPin(env, reviewedLifecycleRemoval),
    additions: report.additions,
    branchId: "slack-groups-channels" as const,
    channelRenames: report.channelRenames,
    diagnostics: [
      ...report.errors.map((message) => ({
        code: "channel_plan_error",
        message,
        scope: {
          actionId: "workspace-directory.slack-groups-channels" as const,
          kind: "action" as const,
        },
        severity: "blocker" as const,
      })),
      ...report.warnings.map((message) => ({
        code: "channel_plan_warning",
        message,
        severity: "warning" as const,
      })),
      {
        code:
          env.orgChannelSyncMode === "live"
            ? "managed_exact_plan_apply"
            : "audit_only_kill_switch",
        message:
          env.orgChannelSyncMode === "live"
            ? "Slack changes are exact-plan, lease-fenced, bounded, and verified by provider readback."
            : "Slack changes remain audit-only until the channel-sync live-mode gate is enabled.",
        severity: "info" as const,
      },
    ],
    execution:
      env.orgChannelSyncMode === "live"
        ? ("managed" as const)
        : ("audit-only" as const),
    killSwitchEngaged: env.orgChannelSyncMode !== "live",
    lifecycle: {
      googleTeamGroupsOutsideAssignmentAllowlist:
        report.lifecycle.googleTeamGroupsOutsideAssignmentAllowlist.map(
          ({ email }) => email,
        ),
      nonstandardPublicChannels: report.lifecycle.nonstandardPublicChannels.map(
        ({ name }) => name,
      ),
      privateChannelRenameCandidates:
        report.lifecycle.privateChannelRenameCandidates.map(
          ({ currentName, expectedName }) => ({ currentName, expectedName }),
        ),
      slackTeamChannelCollisions:
        report.lifecycle.slackTeamChannelCollisions.map(({ name }) => name),
      slackUsersWithoutTeamAssignment:
        report.lifecycle.slackUsersWithoutTeamAssignment,
      verticalRetirementCandidates:
        report.lifecycle.verticalRetirementCandidates.map(({ name }) => name),
    },
    planHash: report.planHash,
    removals: report.removals,
    selectedChannelAdditions:
      env.orgChannelSyncMode === "live" ? report.selectedChannelAdditions : [],
    selectedChannelRename:
      env.orgChannelSyncMode === "live" ? report.selectedChannelRename : null,
    selectedProvenanceChannelRemovals:
      env.orgChannelSyncMode === "live"
        ? report.selectedProvenanceChannelRemovals.map((removal) => ({
            ...removal,
            ...resolveSelectedChannelRemovalIdentity(report.removals, removal),
          }))
        : [],
    selectedRemovalCount:
      env.orgChannelSyncMode === "live"
        ? report.selectedUserGroups.reduce(
            (count, group) =>
              count +
              group.memberRemovals.length +
              group.channelRemovals.length,
            report.selectedProvenanceChannelRemovals.length,
          )
        : 0,
    selectedUserGroupHandles:
      env.orgChannelSyncMode === "live" ? report.selectedUserGroupHandles : [],
    selectedUserGroups:
      env.orgChannelSyncMode === "live"
        ? report.selectedUserGroups.map((group) => ({
            automationOwnership: group.automationOwnership,
            authority: group.authority,
            channelAdditions: group.channelAdditions,
            channelAdditionIds: group.channelAdditions.map(({ id }) => id),
            channelRemovals: group.channelRemovals,
            channelRemovalIds: group.channelRemovals.map(({ id }) => id),
            currentHandle: group.currentHandle,
            currentName: group.currentName,
            desiredName: group.desiredName,
            effectiveAccessAdditions: group.effectiveAccessAdditions,
            expectedSlackUserGroupId: group.expectedSlackUserGroupId,
            handle: group.handle,
            memberAdditions: group.memberAdditions,
            memberRemovalAuthority: group.memberRemovalAuthority,
            memberRemovals: group.memberRemovals,
            requiredChannelIds: group.requiredChannelIds,
            slackUserGroupId: group.slackUserGroupId,
          }))
        : [],
    userGroups: report.userGroups.map((group) => ({
      automationOwnership: group.automationOwnership,
      authority: group.authority,
      channelAdditionIds: group.channelAdditions.map(({ id }) => id),
      channelRemovalIds: group.channelRemovals.map(({ id }) => id),
      currentHandle: group.currentHandle,
      currentName: group.currentName,
      desiredChannelIds: group.desiredChannelIds,
      desiredName: group.desiredName,
      desiredUserIds: group.desiredUserIds,
      handle: group.handle,
      memberAdditions: group.memberAdditions,
      memberAdditionUserIds: group.memberAdditions.map(
        ({ slackUserId }) => slackUserId,
      ),
      memberRemovals: group.memberRemovals,
      memberRemovalUserIds: group.memberRemovals.map(
        ({ slackUserId }) => slackUserId,
      ),
      removalCount: group.memberRemovals.length + group.channelRemovals.length,
      requiredChannelIds: group.requiredChannelIds,
      slackUserGroupId: group.slackUserGroupId,
      status: group.status,
    })),
  });
  if (purpose.kind === "original-target-readback") return branch;
  const selectedUserId = selectedSlackMembershipUserId(branch);
  if (selectedUserId === undefined || branch.execution !== "managed")
    return branch;
  const identities = await runtime.service.readMembershipIdentities(
    [selectedUserId],
    googleUsers,
  );
  return SlackGroupsChannelsBranchPlanSchema.parse({
    ...branch,
    selectedIdentity: {
      slackUserId: selectedUserId,
      googleUserId: identities.get(selectedUserId),
    },
  });
}
async function captureChannelReport(
  runtime: ChannelCaptureRuntime,
  googleUsers: readonly GoogleDirectoryUser[],
  purpose: ChannelCapturePurpose,
  reviewedLifecycleRemoval?: ReviewedSlackLifecycleRemoval,
) {
  const options = {
    allowRemovals: runtime.allowRemovals,
    googleUsers,
    ...(reviewedLifecycleRemoval !== undefined && {
      reviewedLifecycleRemoval,
    }),
  };
  if (
    purpose.kind === "original-target-readback" &&
    purpose.branch.execution === "managed" &&
    purpose.branch.selectedIdentity !== undefined
  ) {
    const pin = purpose.branch.selectedIdentity;
    const read = await runtime.service.readMembershipPlan({
      ...options,
      slackUserId: pin.slackUserId,
      ...(purpose.branch.reviewedLifecycleRemoval !== undefined && {
        reviewedLifecycleReadback: purpose.branch.reviewedLifecycleRemoval,
      }),
    });
    if (
      selectedSlackMembershipUserId(purpose.branch) !== pin.slackUserId ||
      read.googleUserId !== pin.googleUserId
    )
      throw new Error(SLACK_MEMBERSHIP_IDENTITY_CHANGED);
    return read.report;
  }
  return runtime.service.run({ ...options, mode: "audit", trigger: "http" });
}
function reviewedLifecycleBranchPin(
  env: ValidatedEnv,
  reviewedLifecycleRemoval?: ReviewedSlackLifecycleRemoval,
) {
  return reviewedLifecycleRemoval === undefined ||
    env.orgChannelSyncMode !== "live"
    ? {}
    : { reviewedLifecycleRemoval };
}
function resolveSelectedChannelRemovalIdentity(
  removals: readonly {
    channelId: string;
    identity: string;
    slackUserId: string;
  }[],
  selected: {
    channelId: string;
    slackUserId: string;
  },
): {
  identity: string;
} {
  const matches = removals
    .filter(
      ({ channelId, slackUserId }) =>
        channelId === selected.channelId &&
        slackUserId === selected.slackUserId,
    )
    .map(({ identity }) => identity)
    .filter(
      (identity, index, identities) => identities.indexOf(identity) === index,
    );
  const resolvedIdentity = matches.length === 1 ? matches[0] : undefined;
  if (resolvedIdentity === undefined) {
    throw new Error(
      "workspace_directory_selected_slack_removal_identity_unresolved",
    );
  }
  return { identity: resolvedIdentity };
}
async function captureGithub(bindings: WorkspaceSyncRuntimeBindings) {
  const report = await bindings.githubAudit().run();
  return {
    branchId: "github-access" as const,
    contentHash: report.contentHash,
    diagnostics: [
      ...report.errors.map((message) => ({
        code: "github_audit_error",
        message,
        scope: { kind: "audit" as const, provider: "github" as const },
        severity: "blocker" as const,
      })),
      ...report.warnings.map((message) => ({
        code: "github_audit_warning",
        message,
        severity: "warning" as const,
      })),
      {
        code: "audit_only_kill_switch",
        message:
          "GitHub access remains audit-only until the dedicated organization-sync credential, one-change cap, and managed kill switch are explicitly enabled.",
        severity: "info" as const,
      },
    ],
    execution: "audit-only" as const,
    killSwitchEngaged: true,
    proposedChanges: report.proposedChanges,
  };
}
export function captureGithubWriterReadiness(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
) {
  return inspectGithubWriterReadiness(
    {
      auditToken: env.githubAccessAuditToken,
      writerToken: env.githubOrganizationSyncToken,
      mutationDisabled:
        env.githubOrganizationSyncDisabled ||
        env.githubOrganizationSyncMaxChanges !== 1,
    },
    {
      capture: async () => {
        const users = await bindings
          .google("github_writer_readiness", DIRECTORY_READONLY_SCOPE)
          .listAllUsers(crypto.randomUUID());
        // This local planning bound does not alter any environment switch or authorize an apply.
        return captureManagedGithubState(
          bindings,
          { ...env, githubOrganizationSyncMaxChanges: 1 },
          users,
        );
      },
      verifyWriterTenant: () =>
        new GitHubOrganizationApiPort({
          managedTeamPins: bindings.githubPolicy.teamPins,
          managedTeamSlugs: Object.values(bindings.githubPolicy.teamMappings),
          organizationId: env.githubOrganizationSyncOrganizationId,
          organizationLogin: env.githubOrganizationSyncOrganizationLogin,
          samlToken: env.githubAccessAuditToken,
          token: env.githubOrganizationSyncToken,
        }).verifyWriterTenant(),
    },
  );
}
function captureGithubBranch(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  users: readonly GoogleDirectoryUser[],
) {
  if (env.githubAccessAuditDisabled) {
    return Promise.resolve(disabledGitHubAccessPlan());
  }
  if (
    env.githubOrganizationSyncDisabled ||
    env.githubOrganizationSyncMaxChanges === 0
  ) {
    return captureWorkspaceDirectoryComponent(
      "workspace-directory.github-access",
      () => captureGithub(bindings),
    );
  }
  return captureWorkspaceDirectoryComponent(
    "workspace-directory.github-access",
    () => captureManagedGithub(bindings, env, users),
  );
}
function disabledGitHubAccessPlan(
  reason = "github_access_audit_disabled",
): WorkspaceDirectoryPlan["branches"][3] {
  return {
    branchId: "github-access" as const,
    contentHash: null,
    diagnostics: [disabledDiagnostic(reason)],
    execution: "disabled" as const,
    killSwitchEngaged: true as const,
    proposedChanges: [] as const,
  };
}
async function captureManagedGithub(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  users: readonly GoogleDirectoryUser[],
) {
  const captured = await captureManagedGithubState(bindings, env, users);
  return captured.branch;
}
async function captureManagedGithubState(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  users: readonly GoogleDirectoryUser[],
) {
  if (env.githubOrganizationSyncMaxChanges !== 1) {
    throw new Error(GITHUB_ACCESS_KILL_SWITCH_ENGAGED);
  }
  await assertManagedGithubCredentials(env);
  const source = await captureManagedGithubSource(bindings);
  const github = await captureManagedGithubStage(
    "source_github_inventory_unavailable",
    () =>
      new GitHubAccessAuditClient({
        organization: env.githubAccessAuditOrganization,
        token: env.githubAccessAuditToken,
      }).capture(),
  );
  return captureManagedGitHubAccessState(
    users,
    source.google,
    github,
    {
      maxChanges: env.githubOrganizationSyncMaxChanges,
      organizationId: env.githubOrganizationSyncOrganizationId,
      organizationLogin: env.githubOrganizationSyncOrganizationLogin,
      rootGroupEmail: source.rootGroupEmail,
      token: env.githubOrganizationSyncToken,
    },
    source.policy,
  );
}
async function captureManagedGithubSource(
  bindings: WorkspaceSyncRuntimeBindings,
) {
  const employeeEntitlementAuthority = await captureManagedGithubStage(
    "source_employee_authority_unavailable",
    () => bindings.captureEmployeeAuthority(),
  );
  const authority = bindings.githubAuthority();
  const google = await captureManagedGithubStage(
    "source_google_authority_unavailable",
    () =>
      authority.google.capture(
        {
          mappedGroupEmails: [
            ...Object.keys(bindings.githubPolicy.teamMappings),
            ...bindings.githubPolicy.excludedGroupEmails,
          ],
          reportsLookbackDays: bindings.githubPolicy.reportsLookbackDays,
          rootGroupEmail: authority.rootGroupEmail,
        },
        crypto.randomUUID(),
      ),
  );
  return {
    google,
    rootGroupEmail: authority.rootGroupEmail,
    policy: {
      employeeEntitlementAuthority,
      excludedGroupEmails: bindings.githubPolicy.excludedGroupEmails,
      reviewedTeamMemberships: bindings.githubPolicy.reviewedTeamMemberships,
      reviewedDirectGrantRetentions:
        bindings.githubPolicy.reviewedDirectGrantRetentions,
      teamMappings: bindings.githubPolicy.teamMappings,
      teamPins: bindings.githubPolicy.teamPins,
      unmanagedGithubTeams: bindings.githubPolicy.unmanagedGithubTeams,
    },
  };
}
async function captureManagedGithubStage<T>(
  code: string,
  capture: () => Promise<T>,
): Promise<T> {
  try {
    return await capture();
  } catch (error) {
    throw new Error(code, { cause: error });
  }
}
function createManagedGithubPort(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  branch: Extract<
    WorkspaceDirectoryPlan["branches"][3],
    {
      execution: "managed";
    }
  >,
): GitHubOrganizationApiPort {
  if (
    env.githubOrganizationSyncDisabled ||
    env.githubOrganizationSyncMaxChanges !== 1
  ) {
    throw new Error(GITHUB_ACCESS_KILL_SWITCH_ENGAGED);
  }
  if (
    env.githubOrganizationSyncOrganizationId !== branch.organizationId ||
    env.githubOrganizationSyncOrganizationLogin.toLowerCase() !==
      branch.organizationLogin
  ) {
    throw new Error("workspace_directory_github_organization_pin_drift");
  }
  return new GitHubOrganizationApiPort({
    managedTeamPins: bindings.githubPolicy.teamPins,
    managedTeamSlugs: branch.managedTeamSlugs,
    organizationId: branch.organizationId,
    organizationLogin: branch.organizationLogin,
    reviewedDirectGrantRetentions:
      bindings.githubPolicy.reviewedDirectGrantRetentions,
    samlToken: env.githubAccessAuditToken,
    token: env.githubOrganizationSyncToken,
  });
}
async function assertManagedGithubCredentials(
  env: ValidatedEnv,
): Promise<void> {
  if (
    env.githubAccessAuditToken.trim() === "" ||
    env.githubOrganizationSyncToken.trim() === ""
  ) {
    throw new Error("workspace_directory_github_separate_credentials_required");
  }
  await assertDistinctGitHubOrganizationCredentials(
    env.githubAccessAuditToken,
    env.githubOrganizationSyncToken,
  );
}
async function captureAccessGuard(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  users: GoogleDirectoryUser[],
  reviewedLinearSuspension?: ReviewedLinearSuspension,
  scheduledLinearSuspensions = false,
) {
  const automatic =
    reviewedLinearSuspension === undefined &&
    scheduledLinearSuspensions &&
    env.workspaceDirectoryParentEnabled &&
    env.workspaceDirectoryLinearSuspensionsEnabled;
  const auditOptions: AccessGuardAuditOptions = {};
  if (automatic) auditOptions.scheduledLinearSuspension = true;
  if (reviewedLinearSuspension !== undefined)
    auditOptions.linearSuspensionTarget = reviewedLinearSuspension;
  const audited = await bindings
    .accessGuard()
    .service.audit(users, auditOptions);
  const plan =
    reviewedLinearSuspension === undefined
      ? audited
      : selectReviewedLinearSuspension(audited, reviewedLinearSuspension);
  return {
    ...(automatic && { scheduledLinearSuspension: true as const }),
    ...(reviewedLinearSuspension !== undefined && {
      reviewedLinearSuspension,
    }),
    branchId: "access-guard" as const,
    diagnostics: projectAccessGuardDiagnostics(plan),
    execution: "managed" as const,
    killSwitchEngaged: false,
    plan,
  };
}
export function projectAccessGuardDiagnostics(plan: AccessGuardPlan) {
  return [
    ...plan.diagnostics.map((diagnostic) => ({
      code: diagnostic.code,
      ...(diagnostic.code === "provider_readiness" && {
        context: diagnostic.context,
      }),
      message: diagnostic.message,
      scope: accessGuardDiagnosticScope(diagnostic),
      severity:
        diagnostic.level === "error"
          ? ("blocker" as const)
          : ("warning" as const),
    })),
    {
      code: "managed_exact_plan_apply",
      message:
        "Linear suspensions are bound to the reviewed signed plan and verified by readback.",
      severity: "info" as const,
    },
  ];
}
function accessGuardDiagnosticScope(
  diagnostic: AccessGuardPlan["diagnostics"][number],
) {
  if (diagnostic.provider === undefined) return { kind: "authority" } as const;
  if (diagnostic.provider === "linear") {
    return {
      actionId: "workspace-directory.linear-suspensions",
      kind: "action",
    } as const;
  }
  return { kind: "audit", provider: diagnostic.provider } as const;
}
function assertSha256(value: string, errorCode: string): void {
  if (!/^[a-f0-9]{64}$/u.test(value)) throw new Error(errorCode);
}
function isKillSwitchEngaged(branch: { killSwitchEngaged: boolean }): boolean {
  return branch.killSwitchEngaged;
}
function disabledDiagnostic(code: string) {
  return {
    code,
    message:
      code === "action_not_selected"
        ? "The action is outside this plan selection; its provider was not read."
        : "The branch kill switch is engaged.",
    severity: "info" as const,
  };
}
function createIdentitySeedService(
  env: ValidatedEnv,
  google: ReturnType<WorkspaceSyncRuntimeBindings["google"]>,
): GoogleGithubIdentitySeedService | null {
  if (
    !env.workspaceDirectoryGithubIdentitySeedEnabled ||
    env.workspaceDirectoryGithubIdentitySeedMaxChanges < 1 ||
    env.githubAccessAuditOrganization.trim() === "" ||
    env.githubAccessAuditToken.trim() === ""
  ) {
    return null;
  }
  return new GoogleGithubIdentitySeedService({
    github: new GitHubAccessAuditClient({
      organization: env.githubAccessAuditOrganization,
      token: env.githubAccessAuditToken,
    }),
    google,
    maxChanges: env.workspaceDirectoryGithubIdentitySeedMaxChanges,
  });
}
async function captureIdentitySeedPlan(
  env: ValidatedEnv,
  service: GoogleGithubIdentitySeedService | null,
  users: readonly GoogleDirectoryUser[],
  authorityFingerprint: string,
): Promise<GoogleGithubIdentitySeedPlan> {
  if (!env.workspaceDirectoryGithubIdentitySeedEnabled) {
    return { kind: "disabled", reason: GITHUB_IDENTITY_SEED_DISABLED };
  }
  if (!service) {
    return {
      issues: [
        "Google GitHub identity seed configuration or positive change cap is missing",
      ],
      kind: "blocked",
    };
  }
  return service.capture(users, authorityFingerprint);
}
function githubIdentitySeedDiagnostics(
  plan: GoogleGithubIdentitySeedPlan,
): WorkspaceDirectoryPlan["branches"][5]["diagnostics"] {
  if (plan.kind === "disabled") {
    return [
      {
        code: "google_github_identity_seed_disabled",
        message: "Google GitHub identity seeding is disabled.",
        severity: "info" as const,
      },
    ];
  }
  if (plan.kind === "blocked") {
    return plan.issues.map((message) => ({
      code: "google_github_identity_seed_blocked",
      message,
      scope: {
        actionId: "workspace-directory.fanout",
        kind: "action" as const,
      },
      severity: "blocker" as const,
    }));
  }
  const diagnostics: WorkspaceDirectoryPlan["branches"][5]["diagnostics"] = [
    {
      code: "managed_google_github_identity_seed",
      message:
        "Google GitHub identities are ETag-fenced to the signed SAML-backed plan.",
      severity: "info" as const,
    },
  ];
  if (plan.artifact.summary.unresolved > 0) {
    diagnostics.push({
      code: "google_github_identity_seed_unresolved",
      message: `${String(plan.artifact.summary.unresolved)} Google identities lack verified GitHub evidence and will not be changed.`,
      severity: "warning" as const,
    });
  }
  return diagnostics;
}
export async function fingerprintGoogleAuthority(
  users: readonly GoogleDirectoryUser[],
): Promise<string> {
  return sha256Hex(
    JsonValueSchema.parse(
      users
        .map(googleAuthorityFingerprintRecord)
        .toSorted((left, right) => left.id.localeCompare(right.id)),
    ),
  );
}
export function workspaceDirectoryAuthorityRevision(
  googleUserId: string,
  authorityFingerprint: string,
): string {
  return `google-directory:${googleUserId}:${authorityFingerprint}`;
}
export async function readOriginalSlackMembershipObservation(
  env: ValidatedEnv,
  users: readonly GoogleDirectoryUser[],
  planned: SlackGroupsChannelsPlan,
  channelRuntime: {
    service: Pick<OrgChannelSyncService, "readOriginalMembershipObservation">;
  },
): Promise<JsonValue> {
  if (
    env.orgChannelSyncMode !== "live" ||
    env.orgChannelSyncDisabled ||
    planned.execution !== "managed" ||
    planned.selectedIdentity === undefined
  )
    throw new Error("workspace_slack_membership_observation_pin_required");
  const observed =
    await channelRuntime.service.readOriginalMembershipObservation({
      googleUsers: users,
      ...planned.selectedIdentity,
    });
  return observeOriginalSlackMembershipTarget(planned, observed);
}
