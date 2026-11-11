import { z } from "zod";

const CatalogSlugSchema = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
const CatalogTextSchema = z.string().trim().min(1);
const RepositoryPathSchema = z
  .string()
  .min(1)
  .refine(
    (value) =>
      !value.startsWith("/") &&
      !value.endsWith("/") &&
      !value.includes("\\") &&
      !value
        .split("/")
        .some(
          (segment) => segment === "" || segment === "." || segment === "..",
        ),
    "repository path must be normalized and repository-relative",
  )
  .brand<"RepositoryPath">();
const SystemDescriptorIdSchema = z
  .enum([
    "ashby",
    "attio",
    "cloudflare-d1",
    "cloudflare-kv",
    "github",
    "google-drive",
    "google-groups",
    "google-workspace",
    "linear",
    "pagerduty",
    "sentry",
    "slack",
    "trycomp",
  ])
  .brand<"SystemDescriptorId">();

const WorkspaceDirectoryExecutionModeSchema = z.enum(["managed", "audit-only"]);

const SafeDocumentationTextSchema = CatalogTextSchema.max(240).refine(
  (value) =>
    !value.includes("@") &&
    !/(?:xox[abprs]-|gh[opsu]_|-----BEGIN|Bearer\s+[A-Za-z0-9_-]{12,})/iu.test(
      value,
    ),
  "documentation text must not contain identity or credential material",
);
export const WorkspaceDirectoryScheduledExecutionSchema = z.enum([
  "audit-only",
  "automatic",
  "bounded-automatic",
  "manual-review",
  "rollout-gated",
]);

export const SLACK_PROFILE_MANAGED_FIELD_IDS = [
  "reportsTo",
  "manages",
  "team",
  "linkedin",
  "title",
] as const;
export type SlackProfileManagedFieldId =
  (typeof SLACK_PROFILE_MANAGED_FIELD_IDS)[number];
export const SLACK_PROFILE_MANAGED_FIELD_LABELS = {
  linkedin: "LinkedIn",
  manages: "manages",
  reportsTo: "reports to",
  team: "team",
  title: "title",
} as const satisfies Readonly<Record<SlackProfileManagedFieldId, string>>;

export const WorkspaceDirectoryBranchIdSchema = z.enum([
  "slack-profiles",
  "drive-org-chart",
  "slack-groups-channels",
  "github-access",
  "access-guard",
  "identity-provisioning",
  "trycomp-people",
  "slack-names",
  "linear-profiles",
  "google-group-cleanup",
  "pagerduty-teams",
  "sentry-memberships",
]);

export const WorkspaceDirectoryTargetSchema = z
  .strictObject({
    effect: z.enum(["reconcile", "report"]),
    mode: WorkspaceDirectoryExecutionModeSchema,
    surface: SafeDocumentationTextSchema,
    systemId: SystemDescriptorIdSchema,
    verification: z.enum([
      "content-hash",
      "desired-state-hash",
      "plan-digest",
      "provider-report",
      "target-readback",
    ]),
  })
  .superRefine((target, context) => {
    if (target.mode === "managed" && target.effect !== "reconcile") {
      context.addIssue({
        code: "custom",
        message: "managed targets must reconcile state",
      });
    }
    if (target.mode === "audit-only" && target.effect !== "report") {
      context.addIssue({
        code: "custom",
        message: "audit-only targets must report state",
      });
    }
    if (
      target.mode === "managed" &&
      target.verification !== "target-readback"
    ) {
      context.addIssue({
        code: "custom",
        message: "managed targets require target readback",
      });
    }
    if (
      target.mode === "audit-only" &&
      target.verification === "target-readback"
    ) {
      context.addIssue({
        code: "custom",
        message: "audit-only targets cannot claim target readback",
      });
    }
  })
  .readonly();

const BRANCH_BASE_SHAPE = {
  displayName: SafeDocumentationTextSchema,
  enabledExecution: WorkspaceDirectoryExecutionModeSchema,
  relatedIntegrationId: CatalogSlugSchema.nullable(),
  relatedScheduleJobId: CatalogSlugSchema.nullable(),
  relatedSyncPipelineId: CatalogSlugSchema.nullable(),
  rolloutState: z.enum(["enabled", "disabled"]),
  scheduledExecution: WorkspaceDirectoryScheduledExecutionSchema,
  sourcePaths: z
    .tuple([RepositoryPathSchema])
    .rest(RepositoryPathSchema)
    .readonly(),
  sourceSystemIds: z
    .tuple([SystemDescriptorIdSchema])
    .rest(SystemDescriptorIdSchema)
    .readonly(),
  summary: SafeDocumentationTextSchema,
  targets: z
    .tuple([WorkspaceDirectoryTargetSchema])
    .rest(WorkspaceDirectoryTargetSchema)
    .readonly(),
} as const;

const SlackProfilesBranchSchema = z
  .strictObject({ ...BRANCH_BASE_SHAPE, branchId: z.literal("slack-profiles") })
  .readonly();
const DriveOrgChartBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("drive-org-chart"),
  })
  .readonly();
const SlackGroupsChannelsBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("slack-groups-channels"),
  })
  .readonly();
const GitHubAccessBranchSchema = z
  .strictObject({ ...BRANCH_BASE_SHAPE, branchId: z.literal("github-access") })
  .readonly();
const AccessGuardBranchSchema = z
  .strictObject({ ...BRANCH_BASE_SHAPE, branchId: z.literal("access-guard") })
  .readonly();
const IdentityProvisioningBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("identity-provisioning"),
  })
  .readonly();
const TrycompPeopleBranchSchema = z
  .strictObject({ ...BRANCH_BASE_SHAPE, branchId: z.literal("trycomp-people") })
  .readonly();
const SlackNamesBranchSchema = z
  .strictObject({ ...BRANCH_BASE_SHAPE, branchId: z.literal("slack-names") })
  .readonly();
const LinearProfilesBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("linear-profiles"),
  })
  .readonly();
const GoogleGroupCleanupBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("google-group-cleanup"),
  })
  .readonly();
const PagerDutyTeamsBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("pagerduty-teams"),
  })
  .readonly();
const SentryMembershipsBranchSchema = z
  .strictObject({
    ...BRANCH_BASE_SHAPE,
    branchId: z.literal("sentry-memberships"),
  })
  .readonly();

function branchValidationIssues(
  branch: Omit<z.output<typeof SlackProfilesBranchSchema>, "branchId">,
): string[] {
  const issues: string[] = [];
  if (new Set(branch.sourceSystemIds).size !== branch.sourceSystemIds.length) {
    issues.push("source systems must be unique");
  }
  if (
    (branch.relatedScheduleJobId === null) !==
    (branch.relatedSyncPipelineId === null)
  ) {
    issues.push("related schedule and sync pipeline must be declared together");
  }
  const targetIds = branch.targets.map(({ systemId }) => systemId);
  if (new Set(targetIds).size !== targetIds.length) {
    issues.push("target systems must be unique per branch");
  }
  const hasManagedTarget = branch.targets.some(
    ({ mode }) => mode === "managed",
  );
  if (branch.enabledExecution === "managed" && !hasManagedTarget) {
    issues.push("managed branches require a managed target");
  }
  if (branch.enabledExecution === "audit-only" && hasManagedTarget) {
    issues.push("audit-only branches cannot contain managed targets");
  }
  if (
    branch.enabledExecution === "audit-only" &&
    branch.scheduledExecution !== "audit-only"
  ) {
    issues.push("audit-only branches require audit-only scheduled execution");
  }
  if (
    branch.enabledExecution === "managed" &&
    branch.scheduledExecution === "audit-only"
  ) {
    issues.push("managed branches require an explicit scheduled write policy");
  }
  return issues;
}

export const WorkspaceDirectoryFlowSchema = z
  .strictObject({
    authoritySystemId: z.literal("google-workspace"),
    branches: z
      .tuple([
        SlackProfilesBranchSchema,
        DriveOrgChartBranchSchema,
        SlackGroupsChannelsBranchSchema,
        GitHubAccessBranchSchema,
        AccessGuardBranchSchema,
        IdentityProvisioningBranchSchema,
      ])
      .rest(
        z.union([
          TrycompPeopleBranchSchema,
          SlackNamesBranchSchema,
          LinearProfilesBranchSchema,
          GoogleGroupCleanupBranchSchema,
          PagerDutyTeamsBranchSchema,
          SentryMembershipsBranchSchema,
        ]),
      )
      .refine(
        (branches) =>
          new Set(branches.map(({ branchId }) => branchId)).size ===
          branches.length,
        "optional workspace branches must be unique",
      )
      .readonly(),
    operationId: z.literal("workspace-directory.reconcile"),
    policyVersion: z.literal("workspace-directory-v11"),
    requiredRole: z.literal("operations-admin"),
    requiredScope: z.literal("workspace-directory:apply"),
    schemaVersion: z.literal(1),
  })
  .superRefine((flow, context) => {
    const relatedIntegrationIds = flow.branches.flatMap(
      ({ relatedIntegrationId }) =>
        relatedIntegrationId === null ? [] : [relatedIntegrationId],
    );
    if (new Set(relatedIntegrationIds).size !== relatedIntegrationIds.length) {
      context.addIssue({
        code: "custom",
        message: "related integrations must be unique",
      });
    }
    for (const [index, branch] of flow.branches.entries()) {
      for (const message of branchValidationIssues(branch)) {
        context.addIssue({
          code: "custom",
          message,
          path: ["branches", index],
        });
      }
    }
  })
  .readonly();

export type WorkspaceDirectoryBranchId = z.output<
  typeof WorkspaceDirectoryBranchIdSchema
>;
export type WorkspaceDirectoryTarget = z.output<
  typeof WorkspaceDirectoryTargetSchema
>;
export type WorkspaceDirectoryFlow = z.output<
  typeof WorkspaceDirectoryFlowSchema
>;
export type WorkspaceDirectoryBranch =
  WorkspaceDirectoryFlow["branches"][number];
export type WorkspaceDirectoryScheduledExecution = z.output<
  typeof WorkspaceDirectoryScheduledExecutionSchema
>;

export const WORKSPACE_DIRECTORY_FLOW = WorkspaceDirectoryFlowSchema.parse({
  authoritySystemId: "google-workspace",
  branches: [
    {
      branchId: "slack-profiles",
      displayName: "Slack profiles",
      enabledExecution: "managed",
      relatedIntegrationId: "google-workspace-slack-profile-sync",
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-directory-slack-profiles",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
      ],
      sourceSystemIds: ["google-workspace", "slack"],
      summary:
        "Reconciles one exact matched Google-derived profile update per scheduled run with exact Slack readback; profile clears remain reviewed.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: `Profile fields: ${humanList(
            SLACK_PROFILE_MANAGED_FIELD_IDS.map(
              (fieldId) => SLACK_PROFILE_MANAGED_FIELD_LABELS[fieldId],
            ),
          )}`,
          systemId: "slack",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "drive-org-chart",
      displayName: "Organization chart",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-directory-org-chart",
      rolloutState: "enabled",
      scheduledExecution: "automatic",
      sourcePaths: [
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
      ],
      sourceSystemIds: ["google-workspace"],
      summary:
        "Reconciles the pinned organization-chart document from the reviewed directory snapshot.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "Managed organization-chart document",
          systemId: "google-drive",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "slack-groups-channels",
      displayName: "Slack groups and channels",
      enabledExecution: "managed",
      relatedIntegrationId: "google-groups-slack-channel-sync",
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-groups-slack-access",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "apps/internal-automations/src/workspace-sync-host/channel-settings.ts",
        "apps/internal-automations/src/workspace-sync-host/channel-bindings.ts",
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
      ],
      sourceSystemIds: ["google-workspace", "google-groups", "slack"],
      summary:
        "Reconciles Google groups with Slack through immutable, automation-owned groups and bounded additions; every removal requires a reviewed plan.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface:
            "User-group membership, user-group channel assignments, and supported channel names",
          systemId: "slack",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "github-access",
      displayName: "GitHub access",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-workspace-github-access",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "apps/internal-automations/src/workspace-sync-host/github-settings.ts",
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
        "apps/internal-automations/src/workspace-sync-host/scheduler-bindings.ts",
      ],
      sourceSystemIds: ["google-workspace", "github"],
      summary:
        "Applies at most one additive Google-derived organization or managed-team change per scheduled run with exact provider preflight and readback; removals remain reviewed.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface:
            "Organization membership and explicitly managed team membership",
          systemId: "github",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "access-guard",
      displayName: "Account access guard",
      enabledExecution: "managed",
      relatedIntegrationId: "access-guard-slack-audit",
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "access-guard",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "apps/internal-automations/src/workspace-sync-host/access-guard-settings.ts",
        "apps/internal-automations/src/workspace-sync-host/access-guard-bindings.ts",
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
      ],
      sourceSystemIds: [
        "google-workspace",
        "ashby",
        "attio",
        "github",
        "linear",
        "pagerduty",
        "slack",
      ],
      summary:
        "Audits provider accounts and suspends one eligible inactive Linear identity through the enabled signed scheduler; exact human-reviewed plans remain supported.",
      targets: [
        {
          effect: "report",
          mode: "audit-only",
          surface: "User accounts; invitation state is not observed",
          systemId: "ashby",
          verification: "provider-report",
        },
        {
          effect: "report",
          mode: "audit-only",
          surface: "Workspace members; invitation state is not observed",
          systemId: "attio",
          verification: "provider-report",
        },
        {
          effect: "report",
          mode: "audit-only",
          surface: "Organization accounts and pending invitations",
          systemId: "github",
          verification: "provider-report",
        },
        {
          effect: "reconcile",
          mode: "managed",
          surface:
            "One signed inactive-account suspension with provider readback",
          systemId: "linear",
          verification: "target-readback",
        },
        {
          effect: "report",
          mode: "audit-only",
          surface: "User accounts",
          systemId: "pagerduty",
          verification: "provider-report",
        },
        {
          effect: "report",
          mode: "audit-only",
          surface: "Workspace account lifecycle",
          systemId: "slack",
          verification: "provider-report",
        },
      ],
    },
    {
      branchId: "identity-provisioning",
      displayName: "Google identity fields",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: null,
      relatedSyncPipelineId: null,
      rolloutState: "disabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
      ],
      sourceSystemIds: ["google-workspace"],
      summary:
        "Retains the Google-owned SarjIdentity schema without GitHub-to-Google writes.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "SarjIdentity schema",
          systemId: "google-workspace",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "trycomp-people",
      displayName: "Trycomp people",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-workspace-trycomp-people",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "vendor/workspace-sync/provenance.json",
        "apps/internal-automations/src/workspace-sync-host/runtime-bindings.ts",
      ],
      sourceSystemIds: ["google-workspace", "google-groups", "trycomp"],
      summary:
        "Reconciles one exact Google-authoritative Trycomp identity through a signed plan, durable mutation journal, and provider readback.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface:
            "One employee invitation, reactivation, or authorized deactivation",
          systemId: "trycomp",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "slack-names",
      displayName: "Slack real names",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-directory-slack-real-names",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: ["vendor/workspace-sync/provenance.json"],
      sourceSystemIds: ["google-workspace", "slack"],
      summary:
        "Repairs one exact nonprivileged email-default real name from reviewed Google authority.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "One reviewed real name",
          systemId: "slack",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "linear-profiles",
      displayName: "Linear full names",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-directory-linear-profile-names",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: ["vendor/workspace-sync/provenance.json"],
      sourceSystemIds: ["google-workspace", "linear"],
      summary:
        "Repairs one exact nonprivileged email-default full name from reviewed Google authority.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "One reviewed full name",
          systemId: "linear",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "google-group-cleanup",
      displayName: "Google Group cleanup",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-directory-group-cleanup",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "apps/internal-automations/src/workspace-sync-host/http/google-group-cleanup-router.ts",
      ],
      sourceSystemIds: ["google-workspace"],
      summary:
        "Removes one original direct membership after positive inactive Google identity authority and parent verification.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "One inactive direct group member",
          systemId: "google-groups",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "pagerduty-teams",
      displayName: "PagerDuty teams",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-workspace-pagerduty-teams",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "apps/internal-automations/src/workspace-sync-host/http/pagerduty-team-router.ts",
      ],
      sourceSystemIds: ["google-workspace"],
      summary:
        "Adds or updates one original ordinary employee team membership; removals remain audit-only.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "One reviewed team member role",
          systemId: "pagerduty",
          verification: "target-readback",
        },
      ],
    },
    {
      branchId: "sentry-memberships",
      displayName: "Sentry memberships",
      enabledExecution: "managed",
      relatedIntegrationId: null,
      relatedScheduleJobId: "organization-sync",
      relatedSyncPipelineId: "google-workspace-sentry-memberships",
      rolloutState: "enabled",
      scheduledExecution: "bounded-automatic",
      sourcePaths: [
        "apps/internal-automations/src/workspace-sync-host/http/sentry-workspace-router.ts",
      ],
      sourceSystemIds: ["google-workspace"],
      summary:
        "Adds one original ordinary employee membership or repairs its reviewed Sentry team access; removals are unsupported.",
      targets: [
        {
          effect: "reconcile",
          mode: "managed",
          surface: "One reviewed organization and team membership",
          systemId: "sentry",
          verification: "target-readback",
        },
      ],
    },
  ],
  operationId: "workspace-directory.reconcile",
  policyVersion: "workspace-directory-v11",
  requiredRole: "operations-admin",
  requiredScope: "workspace-directory:apply",
  schemaVersion: 1,
});

export const WORKSPACE_DIRECTORY_BRANCHES = WORKSPACE_DIRECTORY_FLOW.branches;

export function workspaceDirectoryBranch(
  branchId: WorkspaceDirectoryBranchId,
): WorkspaceDirectoryBranch {
  const branch = WORKSPACE_DIRECTORY_BRANCHES.find(
    (candidate) => candidate.branchId === branchId,
  );
  if (branch === undefined)
    throw new Error(`workspace directory branch ${branchId} is missing`);
  return branch;
}

export function workspaceDirectorySourceSystems(): readonly string[] {
  return uniqueSystems(
    WORKSPACE_DIRECTORY_BRANCHES.flatMap(
      ({ sourceSystemIds }) => sourceSystemIds,
    ),
  );
}

export function workspaceDirectoryTargetSystems(): readonly string[] {
  return uniqueSystems(
    WORKSPACE_DIRECTORY_BRANCHES.flatMap(({ targets }) =>
      targets.map(({ systemId }) => systemId),
    ),
  );
}

function uniqueSystems(systemIds: readonly string[]): readonly string[] {
  return [...new Set(systemIds)];
}

function humanList(values: readonly string[]): string {
  if (values.length < 2) return values[0] ?? "";
  return `${values.slice(0, -1).join(", ")}, and ${values.at(-1) ?? ""}`;
}
