import {
  defineOperation,
  OperationContractError,
  OperationSourceError,
  type RegisteredOperation,
} from "../operations/registry.ts";
import {
  JsonValueSchema,
  type ManagedChange,
  type SourceFingerprint,
} from "../operations/schemas.ts";
import { trycompManagedSlice } from "../trycomp/reviewed-identity.ts";
import {
  WORKSPACE_DIRECTORY_ACTION_IDS,
  WorkspaceDirectoryChangeDetailsSchema,
  WorkspaceDirectoryOperationInputSchema,
  type WorkspaceDirectoryPlan,
} from "./contracts.ts";
import { driveOrgChartManagedSlice } from "./drive-org-chart-artifact.ts";
import {
  WORKSPACE_DIRECTORY_FLOW,
  workspaceDirectorySourceSystems,
  workspaceDirectoryTargetSystems,
} from "./flow.ts";
import {
  githubAccessAfterSlice,
  githubAccessBeforeSlice,
} from "./github-access-managed.ts";
import {
  fanoutSlice,
  slackGroupsChannelsAfterSlice,
  slackGroupsChannelsBeforeSlice,
  slackProfilesAfterSlice,
  slackProfilesBeforeSlice,
} from "./managed-slices.ts";
import {
  IDENTITY_TRANSITION_EXCLUSION,
  workspaceObservationCarrier,
} from "./observation-carrier.ts";
import { readWorkspaceDirectoryManagedSlice } from "./read-workspace-directory-managed-slice.ts";
import {
  googleGroupCleanupManagedSlice,
  googleGroupCleanupResourceId,
} from "./reviewed-google-group-cleanup.ts";
import {
  reviewedNameManagedSlice,
  reviewedNameSourceIdentity,
} from "./reviewed-name-plan.ts";
import {
  pagerDutyTeamManagedSlice,
  pagerDutyTeamResourceId,
} from "./reviewed-pagerduty-team.ts";
import {
  type ReviewedSentryWorkspace,
  sentryWorkspaceManagedSlice,
  sentryWorkspaceResourceId,
} from "./reviewed-sentry-workspace.ts";
import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";
import { workspaceDirectoryOperationDiagnostics } from "./workspace-directory-operation-diagnostics.ts";

export const WORKSPACE_DIRECTORY_OPERATION_ID =
  WORKSPACE_DIRECTORY_FLOW.operationId;
export const WORKSPACE_DIRECTORY_FANOUT_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.fanout;
export const WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.githubAccess;
export const WORKSPACE_DIRECTORY_DRIVE_ORG_CHART_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.driveOrgChart;
export const WORKSPACE_DIRECTORY_LINEAR_SUSPENSIONS_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions;
export const WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels;
export const WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.slackProfiles;
export const WORKSPACE_DIRECTORY_TRYCOMP_ACTION_ID =
  WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople;
const WorkspaceDirectoryJsonDetailsSchema =
  WorkspaceDirectoryChangeDetailsSchema.transform((details) =>
    JsonValueSchema.parse(details),
  );

export function createWorkspaceDirectoryOperation(
  runtime: WorkspaceDirectoryRuntime,
): RegisteredOperation {
  return defineOperation({
    actionIds: Object.values(WORKSPACE_DIRECTORY_ACTION_IDS),
    applyChange: () =>
      Promise.reject(
        new Error("workspace_directory_requires_cloudflare_workflow"),
      ),
    async buildPlan(input) {
      let plan: WorkspaceDirectoryPlan;
      if ("reviewedSlackLifecycleRemoval" in input)
        plan = await runtime.capture(
          input.includedActionIds,
          input.reviewedSlackLifecycleRemoval,
        );
      else if ("reviewedLinearSuspension" in input)
        plan = await runtime.capture(
          input.includedActionIds,
          undefined,
          input.reviewedLinearSuspension,
        );
      else if ("reviewedGoogleGroupCleanup" in input)
        plan = await runtime.capture(
          input.includedActionIds,
          undefined,
          undefined,
          input.reviewedGoogleGroupCleanup,
        );
      else plan = await runtime.capture(input.includedActionIds);
      const includedActionIds: null | ReadonlySet<string> =
        input.includedActionIds === null
          ? null
          : new Set(input.includedActionIds);
      if (
        plan.branches[5].schemaPlan.kind === "not-selected" &&
        (includedActionIds === null
          ? runtime.identityTransitionsExcluded !== true
          : includedActionIds.has(WORKSPACE_DIRECTORY_FANOUT_ACTION_ID))
      ) {
        throw new OperationContractError(
          "workspace-directory.google-identity-schema",
        );
      }
      const diagnostics = materializeWorkspaceDirectoryPlanStage(
        "workspace-directory.plan-diagnostics",
        () => workspaceDirectoryOperationDiagnostics(plan, includedActionIds),
      );
      return {
        applicable: diagnostics.every(
          (diagnostic) =>
            diagnostic.severity !== "blocker" ||
            diagnostic.actionId !== undefined,
        ),
        changes: [
          ...(includedActionIds === null &&
          runtime.identityTransitionsExcluded === true
            ? [workspaceObservationCarrier(plan)]
            : []),
          ...materializeWorkspaceDirectoryPlanStage(
            "workspace-directory.plan-changes",
            () =>
              workspaceDirectoryChanges(plan).filter(
                ({ actionId }) =>
                  includedActionIds === null || includedActionIds.has(actionId),
              ),
          ),
        ],
        diagnostics,
        sourceFingerprints: materializeWorkspaceDirectoryPlanStage(
          "workspace-directory.plan-source-fingerprints",
          () => workspaceDirectorySourceFingerprints(plan, includedActionIds),
        ),
      };
    },
    detailsSchema: WorkspaceDirectoryJsonDetailsSchema,
    inputSchema: WorkspaceDirectoryOperationInputSchema,
    metadata: {
      destructive: true,
      execution: "workflow",
      requiredRole: WORKSPACE_DIRECTORY_FLOW.requiredRole,
      requiredScope: WORKSPACE_DIRECTORY_FLOW.requiredScope,
      risk: "high",
      sourceSystems: [...workspaceDirectorySourceSystems()],
      summary:
        "Plan one Google-authoritative fan-out for reviewed Slack profiles and access, kill-switched GitHub access, Drive, Google SarjIdentity fields, Linear suspensions, and read-only provider inventories.",
      supportsApply: true,
      supportsPlan: true,
      targetSystems: [...workspaceDirectoryTargetSystems()],
    },
    name: WORKSPACE_DIRECTORY_OPERATION_ID,
    policyVersion: WORKSPACE_DIRECTORY_FLOW.policyVersion,
    readManagedSlice: (change) =>
      readWorkspaceDirectoryManagedSlice(runtime, change),
    async readSourceFingerprints(input) {
      const includes = (actionId: string) =>
        input.includedActionIds === null ||
        input.includedActionIds.some((id) => id === actionId);
      const [
        googleAuthorityFingerprint,
        githubAccessAuthorityFingerprint,
        githubIdentityFingerprint,
        trycompAuthorityFingerprint,
      ] = await Promise.all([
        readWorkspaceSource(
          "source_workspace_google_directory_unavailable",
          () => runtime.readAuthorityFingerprint(),
        ),
        includes(WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID)
          ? readWorkspaceSource(
              "source_workspace_github_access_unavailable",
              () => runtime.readGitHubAccessAuthorityFingerprint(),
            )
          : Promise.resolve(null),
        includes(WORKSPACE_DIRECTORY_FANOUT_ACTION_ID) &&
        runtime.identityTransitionsExcluded !== true
          ? readWorkspaceSource(
              "source_workspace_github_identity_unavailable",
              () => runtime.readGithubIdentitySourceFingerprint(),
            )
          : Promise.resolve(null),
        includes(WORKSPACE_DIRECTORY_TRYCOMP_ACTION_ID)
          ? readWorkspaceSource("source_workspace_trycomp_unavailable", () =>
              runtime.readTrycompSourceFingerprint(),
            )
          : Promise.resolve(null),
      ]);
      const nameSources = await readNameSources(runtime, includes);
      return [
        ...identityTransitionExclusionFingerprints(
          runtime.identityTransitionsExcluded === true,
          input.includedActionIds === null,
        ),
        ...nameSources,
        ...(trycompAuthorityFingerprint === null
          ? []
          : [
              {
                authority: "google-workspace",
                resourceId: "trycomp-authority",
                resourceType: "group-membership-snapshot",
                version: trycompAuthorityFingerprint,
              },
            ]),
        {
          authority: "google-workspace",
          resourceId: "directory-users",
          resourceType: "directory-snapshot",
          version: googleAuthorityFingerprint,
        },
        ...(githubAccessAuthorityFingerprint === null
          ? []
          : [
              {
                authority: "google-workspace",
                resourceId: "github-access-authority",
                resourceType: "group-membership-snapshot",
                version: githubAccessAuthorityFingerprint,
              },
            ]),
        ...(githubIdentityFingerprint === null
          ? []
          : [
              {
                authority: "github-enterprise-saml",
                resourceId: "organization-identities",
                resourceType: "identity-snapshot",
                version: githubIdentityFingerprint,
              },
            ]),
      ];
    },
  });
}

export function materializeWorkspaceDirectoryPlanStage<Result>(
  component: string,
  build: () => Result,
): Result {
  try {
    return build();
  } catch (error) {
    if (
      error instanceof OperationContractError ||
      error instanceof OperationSourceError
    )
      throw error;
    throw new OperationSourceError(component, { cause: error });
  }
}

async function readWorkspaceSource<T>(
  code: string,
  read: () => Promise<T>,
): Promise<T> {
  try {
    return await read();
  } catch (cause) {
    throw new Error(code, { cause });
  }
}

async function readNameSources(
  runtime: WorkspaceDirectoryRuntime,
  includes: (actionId: string) => boolean,
): Promise<SourceFingerprint[]> {
  const sources = await Promise.all(
    (["slack-names", "linear-profiles"] as const).map(async (branchId) => {
      if (!includes(`workspace-directory.${branchId}`)) return [];
      const version = await readWorkspaceSource(
        branchId === "slack-names"
          ? "source_workspace_slack_names_unavailable"
          : "source_workspace_linear_names_unavailable",
        async () => runtime.readNameSourceFingerprint?.(branchId),
      );
      return version === null || version === undefined
        ? []
        : [
            {
              authority: "google-workspace",
              resourceId: `${branchId}-authority`,
              resourceType: "name-authority-snapshot",
              version,
            },
          ];
    }),
  );
  return sources.flat();
}

export function workspaceDirectoryChanges(
  plan: WorkspaceDirectoryPlan,
): ManagedChange[] {
  return [
    ...googleGroupCleanupChanges(plan),
    ...pagerDutyTeamsChanges(plan),
    ...sentryMembershipChanges(plan),
    ...(plan.branches[5].schemaPlan.kind === "not-selected"
      ? []
      : [fanoutChange(plan)]),
    ...slackProfileChanges(plan),
    ...driveOrgChartChanges(plan),
    ...githubAccessChanges(plan),
    ...slackGroupsChannelsChanges(plan),
    ...linearSuspensionChanges(plan),
    ...trycompChanges(plan),
    ...nameChanges(plan),
  ];
}

function sentryMembershipChanges(
  plan: WorkspaceDirectoryPlan,
): ManagedChange[] {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "sentry-memberships",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.diagnostics.some(({ severity }) => severity === "blocker")
  ) {
    return [];
  }
  const action = branch.reviewed.action;
  return [
    {
      actionId: WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships,
      after: sentryWorkspaceManagedSlice(branch.reviewed, "converged"),
      before: sentryWorkspaceManagedSlice(branch.reviewed, "pending"),
      details: JsonValueSchema.parse({ kind: "sentry-memberships", plan }),
      display: `Apply one reviewed Sentry ${action.type} action for ${action.email}.`,
      kind: sentryChangeKind(action.type),
      reason:
        action.type === "remove-organization-member"
          ? "The exact ordinary Sentry membership is pinned to an inactive Google identity and fresh immutable Sentry tenant and actor evidence."
          : "The exact additive action is pinned to Google identity, contractor authority, and immutable Sentry tenant and actor evidence.",
      resource: {
        id: sentryWorkspaceResourceId(branch.reviewed),
        type: "sentry-membership",
      },
      risk: action.type === "remove-organization-member" ? "high" : "medium",
    },
  ];
}

function sentryChangeKind(
  type: ReviewedSentryWorkspace["action"]["type"],
): "add" | "change" | "remove" {
  if (type === "remove-organization-member") return "remove";
  return type === "invite" ? "add" : "change";
}

function pagerDutyTeamsChanges(plan: WorkspaceDirectoryPlan): ManagedChange[] {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "pagerduty-teams",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.diagnostics.some(({ severity }) => severity === "blocker")
  )
    return [];
  const { action } = branch.reviewed;
  return [
    {
      actionId: WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
      before: pagerDutyTeamManagedSlice(branch.reviewed, "pending"),
      after: pagerDutyTeamManagedSlice(branch.reviewed, "converged"),
      details: JsonValueSchema.parse({ kind: branch.branchId, plan }),
      display: `Set ${action.email} to ${action.desiredPagerDutyRole} in PagerDuty team ${action.pagerDutyTeamId}.`,
      kind: action.type === "add" ? "add" : "change",
      reason:
        "One direct active Google employee membership authorizes this pinned ordinary PagerDuty identity.",
      resource: {
        id: pagerDutyTeamResourceId(branch.reviewed),
        type: "pagerduty-team-membership",
      },
      risk: "high",
    },
  ];
}

function googleGroupCleanupChanges(
  plan: WorkspaceDirectoryPlan,
): ManagedChange[] {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "google-group-cleanup",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewed === null ||
    branch.diagnostics.some(({ severity }) => severity === "blocker")
  )
    return [];
  return [
    {
      actionId: WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
      after: googleGroupCleanupManagedSlice(branch.reviewed, "converged"),
      before: googleGroupCleanupManagedSlice(branch.reviewed, "pending"),
      details: JsonValueSchema.parse({ kind: branch.branchId, plan }),
      display: `Remove inactive ${branch.reviewed.action.memberEmail} from ${branch.reviewed.action.googleGroupEmail}.`,
      kind: "remove",
      reason:
        "The original direct nonprivileged membership has positive immutable inactive Google authority.",
      resource: {
        id: googleGroupCleanupResourceId(branch.reviewed),
        type: "google-group-membership",
      },
      risk: "high",
    },
  ];
}

function nameChanges(plan: WorkspaceDirectoryPlan): ManagedChange[] {
  return plan.branches.flatMap((branch) => {
    if (
      (branch.branchId !== "slack-names" &&
        branch.branchId !== "linear-profiles") ||
      branch.reviewed === null ||
      branch.diagnostics.some(({ severity }) => severity === "blocker")
    )
      return [];
    return {
      actionId: `workspace-directory.${branch.branchId}`,
      after: reviewedNameManagedSlice(branch.reviewed, "converged"),
      before: reviewedNameManagedSlice(branch.reviewed, "pending"),
      details: JsonValueSchema.parse({ kind: branch.branchId, plan }),
      display: `Repair the reviewed ${branch.branchId === "slack-names" ? "Slack real name" : "Linear full name"} for ${branch.reviewed.action.email}.`,
      kind: "change" as const,
      reason:
        "Google full-name authority authorizes exactly one original nonprivileged identity.",
      resource: {
        id: reviewedNameSourceIdentity(branch.reviewed).providerAccountId,
        type: branch.branchId,
      },
      risk: "medium" as const,
    };
  });
}

function trycompChanges(plan: WorkspaceDirectoryPlan): ManagedChange[] {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "trycomp-people",
  );
  if (
    branch?.execution !== "managed" ||
    branch.reviewedPlan.plan.errors.length > 0
  )
    return [];
  const actions = branch.reviewedPlan.plan.actions;
  if (actions.length !== 1) return [];
  return actions.map((action) => {
    let kind: ManagedChange["kind"] = "change";
    if (action.type === "deactivate") kind = "remove";
    else if (action.type === "invite") kind = "add";
    return {
      actionId: WORKSPACE_DIRECTORY_TRYCOMP_ACTION_ID,
      after: JsonValueSchema.parse(
        trycompManagedSlice(branch.reviewedPlan, "converged"),
      ),
      before: JsonValueSchema.parse(
        trycompManagedSlice(branch.reviewedPlan, "pending"),
      ),
      details: JsonValueSchema.parse({ kind: "trycomp-people", plan }),
      display: `${action.type} Trycomp access for ${action.email}.`,
      kind,
      reason:
        "Apply the exact single reviewed identity from verified Google and contractor authority.",
      resource: {
        id: action.type === "invite" ? action.email : action.memberId,
        type: "trycomp-person",
      },
      risk: action.type === "deactivate" ? "high" : "medium",
    };
  });
}

function githubAccessChanges(plan: WorkspaceDirectoryPlan): ManagedChange[] {
  const branch = plan.branches[3];
  if (branch.execution !== "managed" || branch.selectedOperation === null)
    return [];
  const destructive =
    branch.selectedOperation.operation.kind === "remove-organization-member" ||
    branch.selectedOperation.operation.kind === "remove-team-member";
  return [
    {
      actionId: WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID,
      after: githubAccessAfterSlice(branch),
      before: githubAccessBeforeSlice(branch),
      details: JsonValueSchema.parse({ kind: "github-access", plan }),
      display: `Apply one reviewed GitHub ${branch.selectedOperation.operation.kind} operation.`,
      kind: destructive ? "remove" : "change",
      reason:
        "The exact bounded operation derives from verified Google identity and group authority.",
      resource: {
        id: branch.selectedOperation.googleUserId,
        type: "github-organization-access",
      },
      risk: destructive ? "high" : "medium",
    },
  ];
}

function slackProfileChanges(plan: WorkspaceDirectoryPlan): ManagedChange[] {
  const branch = plan.branches[0];
  const blocked = branch.diagnostics.some(
    (diagnostic) =>
      diagnostic.severity === "blocker" &&
      diagnostic.scope?.kind === "action" &&
      diagnostic.scope.actionId ===
        WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID,
  );
  if (branch.execution !== "managed" || branch.changes.length === 0 || blocked)
    return [];
  const destructiveClears = branch.changes.filter(
    ({ reason }) => reason !== "matched",
  ).length;
  return [
    {
      actionId: WORKSPACE_DIRECTORY_SLACK_PROFILES_ACTION_ID,
      after: slackProfilesAfterSlice(branch),
      before: slackProfilesBeforeSlice(branch),
      details: JsonValueSchema.parse({ kind: "slack-profiles", plan }),
      display: `Reconcile ${String(branch.changes.length)} reviewed Slack profile changes${destructiveClears === 0 ? "" : `, including ${String(destructiveClears)} profile clears`}.`,
      kind: destructiveClears > 0 ? "remove" : "change",
      reason:
        "The exact managed profile fields derive from the signed Google Workspace snapshot.",
      resource: { id: "profiles", type: "slack-profile" },
      risk: destructiveClears > 0 ? "high" : "medium",
    },
  ];
}

function fanoutChange(plan: WorkspaceDirectoryPlan): ManagedChange {
  const profiles = plan.branches[0];
  const identitySeed = plan.branches[5].githubIdentitySeed;
  const identityUpdates =
    identitySeed.kind === "managed"
      ? identitySeed.userPlans.filter(({ kind }) => kind === "update").length
      : 0;
  return {
    actionId: WORKSPACE_DIRECTORY_FANOUT_ACTION_ID,
    after: fanoutSlice(plan, "after"),
    before: fanoutSlice(plan, "before"),
    ...(!(identityUpdates === 0) && {
      confirmationCounts: { githubIdentityUpdates: identityUpdates },
    }),
    details: JsonValueSchema.parse({ kind: "fanout", plan }),
    display: `Run the reviewed Workspace directory fan-out: audit ${String(profiles.changes.length)} Slack profile changes; SarjIdentity schema action ${plan.branches[5].schemaPlan.kind}; ${String(identityUpdates)} Google GitHub identity changes.`,
    kind: fanoutActionKind(plan),
    reason:
      "Google Workspace is authoritative; downstream branches derive their desired state from the reviewed snapshot.",
    resource: { id: "fanout", type: "workspace-directory" },
    risk: "medium",
  };
}

function driveOrgChartChanges(plan: WorkspaceDirectoryPlan): ManagedChange[] {
  const branch = plan.branches[1];
  if (
    branch.execution !== "managed" ||
    branch.currentSha256 === branch.desiredSha256
  )
    return [];
  return [
    {
      actionId: WORKSPACE_DIRECTORY_DRIVE_ORG_CHART_ACTION_ID,
      after: driveOrgChartManagedSlice(branch, branch.desiredSha256),
      before: driveOrgChartManagedSlice(branch, branch.currentSha256),
      details: JsonValueSchema.parse({ kind: "drive-org-chart", plan }),
      display: "Publish the reviewed Google Workspace organization chart.",
      kind: "change",
      reason:
        "The pinned Drive document differs from the signed desired content hash.",
      resource: {
        id: branch.fileId ?? "organization-chart",
        type: "google-drive-file",
      },
      risk: "medium",
    },
  ];
}

function slackGroupsChannelsChanges(
  plan: WorkspaceDirectoryPlan,
): ManagedChange[] {
  const branch = plan.branches[2];
  if (
    branch.execution !== "managed" ||
    (branch.selectedChannelAdditions.length === 0 &&
      branch.selectedUserGroupHandles.length === 0 &&
      branch.selectedChannelRename === null &&
      branch.selectedProvenanceChannelRemovals.length === 0)
  ) {
    return [];
  }
  const hasRemoval = branch.selectedRemovalCount > 0;
  return [
    {
      actionId: WORKSPACE_DIRECTORY_SLACK_GROUPS_CHANNELS_ACTION_ID,
      after: slackGroupsChannelsAfterSlice(branch),
      before: slackGroupsChannelsBeforeSlice(branch),
      details: JsonValueSchema.parse({ kind: "slack-groups-channels", plan }),
      display: `Apply one reviewed Slack access batch: ${String(branch.selectedChannelAdditions.length)} direct channel additions, ${String(branch.selectedUserGroupHandles.length)} user groups, ${String(branch.selectedChannelRename === null ? 0 : 1)} channel rename, and ${String(branch.selectedProvenanceChannelRemovals.length)} provenance-backed channel removal.`,
      kind: hasRemoval ? "remove" : "change",
      reason:
        "The exact bounded batch derives from the signed Google Workspace and Slack snapshots.",
      resource: {
        id:
          branch.selectedIdentity?.slackUserId ??
          (branch.selectedChannelAdditions.length > 0
            ? "channel-invitations"
            : "groups-channels"),
        type: "slack-access",
      },
      risk: hasRemoval ? "high" : "medium",
    },
  ];
}

function linearSuspensionChanges(
  plan: WorkspaceDirectoryPlan,
): ManagedChange[] {
  const actions = plan.branches[4].plan?.actions ?? [];
  if (actions.length === 0) return [];
  return [
    {
      actionId: WORKSPACE_DIRECTORY_LINEAR_SUSPENSIONS_ACTION_ID,
      after: linearAccessSlice(actions, false),
      before: linearAccessSlice(actions, true),
      confirmationCounts: { linearSuspensions: actions.length },
      details: JsonValueSchema.parse({
        actions,
        kind: "linear-suspensions",
        ...(plan.branches[4].execution === "managed" &&
          (plan.branches[4].reviewedLinearSuspension !== undefined ||
            plan.branches[4].scheduledLinearSuspension === true) && { plan }),
      }),
      display: `Suspend ${String(actions.length)} Linear ${actions.length === 1 ? "account" : "accounts"} from the reviewed Google Workspace authority snapshot.`,
      kind: "remove",
      reason:
        "The exact Linear identities remain active after their Google Workspace identities were suspended or archived.",
      resource: { id: "suspensions", type: "linear-access" },
      risk: "high",
    },
  ];
}

export function workspaceDirectorySourceFingerprints(
  plan: WorkspaceDirectoryPlan,
  includedActionIds: null | ReadonlySet<string>,
) {
  const identitySeed = plan.branches[5].githubIdentitySeed;
  const fingerprints = [
    ...identityTransitionExclusionFingerprints(
      plan.branches[5].schemaPlan.kind === "not-selected",
      includedActionIds === null,
    ),
    {
      authority: "google-workspace",
      resourceId: "directory-users",
      resourceType: "directory-snapshot",
      version: plan.authorityFingerprint,
    },
  ];
  for (const branch of plan.branches) {
    if (
      (branch.branchId === "slack-names" ||
        branch.branchId === "linear-profiles") &&
      (includedActionIds === null ||
        includedActionIds.has(`workspace-directory.${branch.branchId}`))
    )
      fingerprints.push({
        authority: "google-workspace",
        resourceId: `${branch.branchId}-authority`,
        resourceType: "name-authority-snapshot",
        version: branch.sourceFingerprint,
      });
  }
  const githubAccess = plan.branches[3];
  const trycomp = plan.branches.find(
    (branch) => branch.branchId === "trycomp-people",
  );
  if (
    trycomp?.execution === "managed" &&
    (includedActionIds === null ||
      includedActionIds.has(WORKSPACE_DIRECTORY_TRYCOMP_ACTION_ID))
  ) {
    fingerprints.unshift({
      authority: "google-workspace",
      resourceId: "trycomp-authority",
      resourceType: "group-membership-snapshot",
      version: trycomp.reviewedPlan.sourceFingerprint,
    });
  }
  if (
    githubAccess.execution === "managed" &&
    (includedActionIds === null ||
      includedActionIds.has(WORKSPACE_DIRECTORY_GITHUB_ACCESS_ACTION_ID))
  ) {
    fingerprints.push({
      authority: "google-workspace",
      resourceId: "github-access-authority",
      resourceType: "group-membership-snapshot",
      version: githubAccess.authorityHash,
    });
  }
  if (
    identitySeed.kind === "managed" &&
    (includedActionIds === null ||
      includedActionIds.has(WORKSPACE_DIRECTORY_FANOUT_ACTION_ID))
  ) {
    fingerprints.push({
      authority: "github-enterprise-saml",
      resourceId: "organization-identities",
      resourceType: "identity-snapshot",
      version: identitySeed.githubSourceFingerprint,
    });
  }
  return fingerprints;
}

function identityTransitionExclusionFingerprints(
  excluded: boolean,
  broad: boolean,
): SourceFingerprint[] {
  return excluded && broad
    ? [
        {
          authority: "configuration",
          resourceId: "google-identity-transitions",
          resourceType: "workspace-parent-capability",
          version: IDENTITY_TRANSITION_EXCLUSION,
        },
      ]
    : [];
}

function linearAccessSlice(
  actions: NonNullable<
    WorkspaceDirectoryPlan["branches"][4]["plan"]
  >["actions"],
  active: boolean,
) {
  return JsonValueSchema.parse(
    actions.map(({ accountId, email }) => ({ accountId, active, email })),
  );
}

function fanoutActionKind(
  plan: WorkspaceDirectoryPlan,
): "add" | "change" | "invoke" {
  const identitySeed = plan.branches[5].githubIdentitySeed;
  const hasIdentityUpdates =
    identitySeed.kind === "managed" &&
    identitySeed.userPlans.some(({ kind }) => kind === "update");
  if (plan.branches[5].schemaPlan.kind === "add-fields" || hasIdentityUpdates) {
    return "change";
  }
  return plan.branches[5].schemaPlan.kind === "create" ? "add" : "invoke";
}
