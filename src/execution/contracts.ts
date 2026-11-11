import { dequal } from "dequal";
import { z } from "zod";

import {
  AccessGuardPlanSchema,
  ProviderNameSchema,
} from "../access-guard/model.ts";
import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { GithubAccessAuditReportSchema } from "../github-access-audit/model.ts";
import {
  GitHubDesiredOrganizationAccessSchema,
  GitHubProvisioningBlockerSchema,
  GitHubProvisioningOperationSchema,
} from "../identity-provisioning/github-organization-connector.ts";
import { GoogleGitHubIdentitySeedPlanSchema } from "../identity-sync/google-github-identity-seed-service.ts";
import { SarjIdentitySchemaPlanSchema } from "../org-sync/google-identity-schema.ts";
import { ReviewedSlackLifecycleRemovalSchema } from "../org-sync/reviewed-lifecycle-removal.ts";
import {
  ProviderReadinessContextSchema,
  validateProviderReadinessDiagnosticContext,
} from "../provider-readiness.ts";
import { TrycompReviewedPlanSchema } from "../trycomp/model.ts";
import {
  WORKSPACE_DIRECTORY_FLOW,
  type WorkspaceDirectoryBranchId as SharedWorkspaceDirectoryBranchId,
} from "./flow.ts";
import {
  DesiredManagedFieldsSchema,
  ManagedFieldNameSchema,
} from "./profile-contracts.ts";
import {
  ReviewedGoogleGroupCleanupIntentSchema,
  ReviewedGoogleGroupCleanupSchema,
} from "./reviewed-google-group-cleanup.ts";
import { ReviewedLinearSuspensionSchema } from "./reviewed-linear-suspension.ts";
import {
  ReviewedLinearProfileActionSchema,
  ReviewedSlackNameActionSchema,
} from "./reviewed-name-plan.ts";
import { ReviewedPagerDutyTeamSchema } from "./reviewed-pagerduty-team.ts";
import { ReviewedSentryWorkspaceSchema } from "./reviewed-sentry-workspace.ts";
import {
  ClaimedReviewedProviderIntentSchema,
  ClaimedReviewedSlackLifecycleIntentSchema,
  isReviewedPlanWithinOriginalApproval,
} from "./reviewed-slack-lifecycle-intent.ts";
import { selectedSlackMembershipUserId } from "./selected-slack-membership-user-id.ts";

export type WorkspaceDirectoryBranchId = SharedWorkspaceDirectoryBranchId;
const DiagnosticSeveritySchema = z.enum(["blocker", "warning", "info"]);
const SlackManagedAuthorityKindSchema = z.enum([
  "automation_created",
  "explicitly_adopted",
]);
const SlackGroupStatusSchema = z.enum(["create", "in_sync", "update"]);
const SlackMemberRemovalAuthoritySchema = z.enum([
  "contractor_group_authoritative",
  "explicit_google_lifecycle",
  "google_group_authoritative",
]);
const GoogleLifecycleSchema = z.enum([
  "active",
  "archived",
  "deleted",
  "suspended",
]);
const BranchExecutionSchema = z.enum(["managed", "audit-only", "disabled"]);
const ManagedWorkflowStateSchema = z.enum(["applied", "skipped"]);

export const WORKSPACE_DIRECTORY_ACTION_IDS = {
  driveOrgChart: "workspace-directory.drive-org-chart",
  fanout: "workspace-directory.fanout",
  githubAccess: "workspace-directory.github-access",
  linearSuspensions: "workspace-directory.linear-suspensions",
  slackGroupsChannels: "workspace-directory.slack-groups-channels",
  slackProfiles: "workspace-directory.slack-profiles",
  trycompPeople: "workspace-directory.trycomp-people",
  slackNames: "workspace-directory.slack-names",
  linearProfiles: "workspace-directory.linear-profiles",
  googleGroupCleanup: "workspace-directory.google-group-cleanup",
  pagerDutyTeams: "workspace-directory.pagerduty-teams",
  sentryMemberships: "workspace-directory.sentry-memberships",
} as const;
export const WorkspaceDirectoryAuthorizedActionIdSchema = z.enum(
  Object.values(WORKSPACE_DIRECTORY_ACTION_IDS),
);
export type WorkspaceDirectoryAuthorizedActionId = z.output<
  typeof WorkspaceDirectoryAuthorizedActionIdSchema
>;

export const SlackProfileChangeReasonSchema = z.enum([
  "matched",
  "not_org_participant",
  "slack_orphan",
  "suspended",
]);
export type SlackProfileChangeReason = z.output<
  typeof SlackProfileChangeReasonSchema
>;

const DiagnosticSchema = z
  .strictObject({
    code: z.string().trim().min(1),
    context: ProviderReadinessContextSchema.optional(),
    message: z.string().trim().min(1),
    scope: z
      .discriminatedUnion("kind", [
        z.strictObject({ kind: z.literal("authority") }),
        z.strictObject({
          kind: z.literal("audit"),
          provider: ProviderNameSchema,
        }),
        z.strictObject({
          actionId: WorkspaceDirectoryAuthorizedActionIdSchema,
          kind: z.literal("action"),
        }),
      ])
      .optional(),
    severity: DiagnosticSeveritySchema,
  })
  .superRefine((diagnostic, context) => {
    validateProviderReadinessDiagnosticContext(diagnostic, context);
    if (diagnostic.severity === "blocker" && diagnostic.scope === undefined) {
      context.addIssue({
        code: "custom",
        message: "blocker diagnostics require a scope",
      });
    }
  });

const BRANCH_BASE = {
  diagnostics: z.array(DiagnosticSchema),
  killSwitchEngaged: z.boolean(),
} as const;

const SlackProfileChangesSchema = z
  .array(
    z.strictObject({
      after: DesiredManagedFieldsSchema,
      before: DesiredManagedFieldsSchema,
      changedFields: z.array(ManagedFieldNameSchema).min(1),
      googleUserId: z.string().nullable(),
      identity: z.string().trim().max(320),
      reason: SlackProfileChangeReasonSchema,
      slackUserId: z.string().min(1),
    }),
  )
  .max(1);
const SLACK_PROFILES_BRANCH_BASE = {
  ...BRANCH_BASE,
  branchId: z.literal("slack-profiles"),
} as const;
export const SlackProfilesBranchPlanSchema = z.discriminatedUnion("execution", [
  z.strictObject({
    ...SLACK_PROFILES_BRANCH_BASE,
    changes: SlackProfileChangesSchema,
    execution: z.literal("managed"),
    killSwitchEngaged: z.literal(false),
    planHash: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  z.strictObject({
    ...SLACK_PROFILES_BRANCH_BASE,
    changes: SlackProfileChangesSchema,
    execution: z.literal("audit-only"),
    killSwitchEngaged: z.literal(true),
    planHash: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  z.strictObject({
    ...SLACK_PROFILES_BRANCH_BASE,
    changes: z.tuple([]),
    execution: z.literal("disabled"),
    killSwitchEngaged: z.literal(true),
    planHash: z.null(),
  }),
]);

const DRIVE_ORG_CHART_BRANCH_BASE = {
  ...BRANCH_BASE,
  branchId: z.literal("drive-org-chart"),
  bytes: z.number().int().nonnegative(),
  people: z.number().int().nonnegative(),
  photos: z.number().int().nonnegative(),
} as const;
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
export const DriveOrgChartBranchPlanSchema = z.discriminatedUnion("execution", [
  z.strictObject({
    ...DRIVE_ORG_CHART_BRANCH_BASE,
    currentSha256: Sha256Schema,
    desiredSha256: Sha256Schema,
    fileId: z
      .string()
      .regex(/^[A-Za-z0-9_-]+$/u)
      .optional(),
    execution: z.literal("managed"),
    killSwitchEngaged: z.literal(false),
  }),
  z.strictObject({
    ...DRIVE_ORG_CHART_BRANCH_BASE,
    currentSha256: z.null(),
    desiredSha256: z.null(),
    execution: z.literal("disabled"),
    killSwitchEngaged: z.literal(true),
  }),
]);

const CHANNEL_MEMBERSHIP_CHANGE = {
  channelId: z.string().min(1),
  channelName: z.string().min(1),
  identity: z.email(),
  isPrivate: z.boolean(),
  slackUserId: z.string().min(1),
} as const;
const ChannelMembershipAdditionSchema = z.strictObject(
  CHANNEL_MEMBERSHIP_CHANGE,
);
const ChannelMembershipRemovalSchema = z.strictObject({
  ...CHANNEL_MEMBERSHIP_CHANGE,
  removalAuthority: z.literal("contractor_group_authoritative").optional(),
});
const SelectedProvenanceChannelRemovalSchema = z.strictObject({
  channelId: z.string().min(1),
  channelName: z.string().min(1),
  identity: z.email(),
  isPrivate: z.boolean(),
  slackUserId: z.string().min(1),
});

const ChannelRenameSchema = z.strictObject({
  channelId: z.string().min(1),
  currentName: z.string().min(1),
  expectedName: z.string().min(1),
  isPrivate: z.boolean(),
});
const SlackUserGroupOwnershipSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("legacy_unmanaged") }),
  z.strictObject({
    allowedChannelIds: z.array(z.string().min(1)),
    evidenceDigest: Sha256Schema,
    excludedGoogleGroupIds: z.array(z.string().min(1)),
    kind: z.literal("automation_bootstrap"),
    sourceGoogleGroupIds: z.array(z.string().min(1)).min(1),
  }),
  z.strictObject({
    allowedChannelIds: z.array(z.string().min(1)),
    cutoverRevision: z.string().regex(/^[a-f0-9]{40}$/u),
    evidenceDigest: Sha256Schema,
    excludedGoogleGroupIds: z.array(z.string().min(1)),
    kind: SlackManagedAuthorityKindSchema,
    sourceGoogleGroupIds: z.array(z.string().min(1)).min(1),
  }),
]);
const SlackUserGroupAuthoritySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    email: z.email(),
    excludedEmails: z.array(z.email()).optional(),
    excludedIds: z.array(z.string().min(1)).optional(),
    id: z.string().min(1),
    kind: z.literal("google_group"),
  }),
  z.strictObject({
    emails: z.array(z.email()).min(1),
    excludedEmails: z.array(z.email()),
    excludedIds: z.array(z.string().min(1)),
    ids: z.array(z.string().min(1)).min(1),
    kind: z.literal("google_group_union"),
  }),
]);
const SlackUserGroupMemberReviewSchema = z.strictObject({
  identity: z.email(),
  slackUserId: z.string().regex(/^U[A-Z0-9]+$/u),
});
const SlackChannelIdentityReviewSchema = z.strictObject({
  id: z.string().min(1),
  isArchived: z.boolean(),
  isPrivate: z.boolean(),
  name: z.string().min(1),
});
const SlackUserGroupPlanSchema = z
  .strictObject({
    automationOwnership: SlackUserGroupOwnershipSchema.optional(),
    authority: SlackUserGroupAuthoritySchema.optional(),
    currentHandle: z.string().min(1).nullish(),
    currentName: z.string().min(1).nullish(),
    channelAdditionIds: z.array(z.string().min(1)).optional(),
    channelRemovalIds: z.array(z.string().min(1)).optional(),
    desiredChannelIds: z.array(z.string()),
    desiredName: z.string().min(1).optional(),
    desiredUserIds: z.array(z.string()),
    handle: z.string().min(1),
    memberAdditions: z.array(SlackUserGroupMemberReviewSchema).optional(),
    memberAdditionUserIds: z.array(z.string().min(1)).optional(),
    memberRemovals: z.array(SlackUserGroupMemberReviewSchema).optional(),
    memberRemovalUserIds: z.array(z.string().min(1)).optional(),
    removalCount: z.number().int().nonnegative().default(0),
    requiredChannelIds: z.array(z.string().min(1)).optional(),
    slackUserGroupId: z.string().min(1).nullish(),
    status: SlackGroupStatusSchema,
  })
  .superRefine((group, context) => {
    for (const [members, userIds, path] of [
      [
        group.memberAdditions,
        group.memberAdditionUserIds,
        "memberAdditionUserIds",
      ],
      [
        group.memberRemovals,
        group.memberRemovalUserIds,
        "memberRemovalUserIds",
      ],
    ] as const) {
      if (members === undefined || userIds === undefined) continue;
      const detailedIds = members
        .map(({ slackUserId }) => slackUserId)
        .toSorted();
      if (!dequal(detailedIds, userIds.toSorted())) {
        context.addIssue({
          code: "custom",
          message:
            "Detailed Slack members must match the corresponding user ID list.",
          path: [path],
        });
      }
    }
  });
const SelectedSlackUserGroupReviewSchema = z
  .strictObject({
    automationOwnership: SlackUserGroupOwnershipSchema,
    authority: SlackUserGroupAuthoritySchema,
    channelAdditions: z.array(SlackChannelIdentityReviewSchema).default([]),
    channelAdditionIds: z.array(z.string().min(1)),
    channelRemovals: z.array(SlackChannelIdentityReviewSchema).default([]),
    channelRemovalIds: z.array(z.string().min(1)),
    currentHandle: z.string().min(1).nullable(),
    currentName: z.string().min(1).nullable(),
    desiredName: z.string().min(1),
    effectiveAccessAdditions: z.array(ChannelMembershipAdditionSchema),
    expectedSlackUserGroupId: z.string().min(1).nullable(),
    handle: z.string().min(1),
    memberAdditions: z.array(SlackUserGroupMemberReviewSchema),
    memberRemovalAuthority: SlackMemberRemovalAuthoritySchema,
    memberRemovals: z.array(SlackUserGroupMemberReviewSchema).max(1),
    requiredChannelIds: z.array(z.string().min(1)),
    slackUserGroupId: z.string().min(1).nullable(),
  })
  .superRefine((group, context) => {
    for (const [channels, ids, path] of [
      [group.channelAdditions, group.channelAdditionIds, "channelAdditionIds"],
      [group.channelRemovals, group.channelRemovalIds, "channelRemovalIds"],
    ] as const) {
      if (!dequal(channels.map(({ id }) => id).toSorted(), ids.toSorted())) {
        context.addIssue({
          code: "custom",
          message:
            "Detailed Slack channels must match the corresponding channel ID list.",
          path: [path],
        });
      }
    }
  });
const SlackAccessLifecycleSchema = z.strictObject({
  googleTeamGroupsOutsideAssignmentAllowlist: z.array(z.email()),
  nonstandardPublicChannels: z.array(z.string().min(1)),
  privateChannelRenameCandidates: z.array(
    z.strictObject({
      currentName: z.string().min(1),
      expectedName: z.string().min(1),
    }),
  ),
  slackTeamChannelCollisions: z.array(z.string().min(1)),
  slackUsersWithoutTeamAssignment: z.array(
    z.strictObject({
      identity: z.email().nullable(),
      slackUserId: z.string().min(1),
    }),
  ),
  verticalRetirementCandidates: z.array(z.string().min(1)),
});
const SLACK_GROUPS_CHANNELS_BRANCH_BASE = {
  ...BRANCH_BASE,
  additions: z.array(ChannelMembershipAdditionSchema),
  branchId: z.literal("slack-groups-channels"),
  channelRenames: z.array(ChannelRenameSchema),
  lifecycle: SlackAccessLifecycleSchema,
  removals: z.array(ChannelMembershipRemovalSchema),
  userGroups: z.array(SlackUserGroupPlanSchema),
} as const;
type ChannelMembershipAddition = z.output<
  typeof ChannelMembershipAdditionSchema
>;

function selectedChannelAdditionsMatchPending(branch: {
  additions: readonly ChannelMembershipAddition[];
  selectedChannelAdditions: readonly ChannelMembershipAddition[];
}): boolean {
  return branch.selectedChannelAdditions.every((selected) =>
    branch.additions.some(
      (addition) =>
        addition.channelId === selected.channelId &&
        addition.channelName === selected.channelName &&
        addition.identity === selected.identity &&
        addition.isPrivate === selected.isPrivate &&
        addition.slackUserId === selected.slackUserId,
    ),
  );
}

export const SlackGroupsChannelsBranchPlanSchema = z
  .discriminatedUnion("execution", [
    z.strictObject({
      ...SLACK_GROUPS_CHANNELS_BRANCH_BASE,
      execution: z.literal("managed"),
      killSwitchEngaged: z.literal(false),
      planHash: Sha256Schema,
      selectedChannelAdditions: z
        .array(ChannelMembershipAdditionSchema)
        .max(5)
        .default([]),
      selectedChannelRename: ChannelRenameSchema.nullable(),
      selectedProvenanceChannelRemovals: z
        .array(SelectedProvenanceChannelRemovalSchema)
        .max(1),
      selectedRemovalCount: z.number().int().nonnegative().max(1),
      selectedUserGroupHandles: z.array(z.string().min(1)).max(1),
      selectedUserGroups: z.array(SelectedSlackUserGroupReviewSchema).max(1),
      selectedIdentity: z
        .strictObject({
          googleUserId: GoogleUserIdSchema,
          slackUserId: z.string().regex(/^U[A-Z0-9]+$/u),
        })
        .optional(),
      reviewedLifecycleRemoval: ReviewedSlackLifecycleRemovalSchema.optional(),
    }),
    z.strictObject({
      ...SLACK_GROUPS_CHANNELS_BRANCH_BASE,
      execution: z.literal("audit-only"),
      killSwitchEngaged: z.literal(true),
      planHash: Sha256Schema,
      selectedChannelAdditions: z.tuple([]).default([]),
      selectedChannelRename: z.null().default(null),
      selectedProvenanceChannelRemovals: z.tuple([]).default([]),
      selectedRemovalCount: z.literal(0).default(0),
      selectedUserGroupHandles: z.tuple([]).default([]),
      selectedUserGroups: z.tuple([]).default([]),
    }),
    z.strictObject({
      ...SLACK_GROUPS_CHANNELS_BRANCH_BASE,
      execution: z.literal("disabled"),
      killSwitchEngaged: z.literal(true),
      planHash: z.null(),
      selectedChannelAdditions: z.tuple([]).default([]),
      selectedChannelRename: z.null().default(null),
      selectedProvenanceChannelRemovals: z.tuple([]).default([]),
      selectedRemovalCount: z.literal(0).default(0),
      selectedUserGroupHandles: z.tuple([]).default([]),
      selectedUserGroups: z.tuple([]).default([]),
    }),
  ])
  .superRefine((branch, context) => {
    if (
      branch.execution === "managed" &&
      branch.reviewedLifecycleRemoval !== undefined
    ) {
      const reviewed = branch.reviewedLifecycleRemoval;
      const group = branch.selectedUserGroups[0];
      if (
        branch.selectedRemovalCount !== 1 ||
        branch.selectedUserGroups.length !== 1 ||
        !isExactReviewedGroupRemoval(group, reviewed) ||
        (branch.selectedIdentity !== undefined &&
          branch.selectedIdentity.googleUserId !== reviewed.googleUserId)
      )
        context.addIssue({
          code: "custom",
          message:
            "Reviewed lifecycle pin must match one exact removal-only group delta",
        });
    }
  })
  .superRefine((branch, context) => {
    if (
      branch.execution === "managed" &&
      branch.selectedIdentity !== undefined &&
      selectedSlackMembershipUserId(branch) !==
        branch.selectedIdentity.slackUserId
    ) {
      context.addIssue({
        code: "custom",
        message:
          "Signed Slack identity must match the exact sole membership delta",
      });
    }
    const selectedTargetKinds =
      Number(branch.selectedChannelAdditions.length > 0) +
      Number(branch.selectedChannelRename !== null) +
      Number(branch.selectedUserGroupHandles.length > 0) +
      Number(branch.selectedProvenanceChannelRemovals.length > 0);
    if (selectedTargetKinds > 1) {
      context.addIssue({
        code: "custom",
        message: "Slack plan may select only one target kind per execution",
      });
    }
    const selectedHandles = new Set(branch.selectedUserGroupHandles);
    if (
      branch.selectedUserGroups.length !==
        branch.selectedUserGroupHandles.length ||
      branch.selectedUserGroups.some(
        (group) => !selectedHandles.has(group.handle),
      )
    ) {
      context.addIssue({
        code: "custom",
        message: "selected Slack review details must match handles",
      });
    }
    if (selectedHandles.size !== branch.selectedUserGroupHandles.length) {
      context.addIssue({
        code: "custom",
        message: "selected Slack user groups must be unique",
      });
    }
    if (
      branch.selectedUserGroupHandles.some(
        (handle) =>
          !branch.userGroups.some(
            (group) => group.handle === handle && group.status !== "in_sync",
          ),
      )
    ) {
      context.addIssue({
        code: "custom",
        message: "selected Slack user groups must be pending",
      });
    }
    if (
      branch.selectedChannelRename !== null &&
      !branch.channelRenames.some(
        (rename) =>
          rename.channelId === branch.selectedChannelRename?.channelId &&
          rename.currentName === branch.selectedChannelRename.currentName &&
          rename.expectedName === branch.selectedChannelRename.expectedName,
      )
    ) {
      context.addIssue({
        code: "custom",
        message: "selected Slack rename must be pending",
      });
    }
    if (!selectedChannelAdditionsMatchPending(branch)) {
      context.addIssue({
        code: "custom",
        message:
          "selected channel additions must exactly match pending additions",
      });
    }
    for (const selected of branch.selectedProvenanceChannelRemovals) {
      if (
        !branch.removals.some(
          (removal) =>
            removal.channelId === selected.channelId &&
            removal.channelName === selected.channelName &&
            removal.identity === selected.identity &&
            removal.isPrivate === selected.isPrivate &&
            removal.slackUserId === selected.slackUserId,
        )
      ) {
        context.addIssue({
          code: "custom",
          message:
            "selected provenance removal must exactly match a pending removal",
        });
      }
    }
    const expectedSelectedRemovalCount = branch.selectedUserGroups.reduce(
      (count, group) =>
        count + group.memberRemovals.length + group.channelRemovalIds.length,
      branch.selectedProvenanceChannelRemovals.length,
    );
    if (branch.selectedRemovalCount !== expectedSelectedRemovalCount) {
      context.addIssue({
        code: "custom",
        message:
          "selected Slack removal count must match the cap-one selected batch",
      });
    }
  });

const GITHUB_ACCESS_BRANCH_BASE = {
  ...BRANCH_BASE,
  branchId: z.literal("github-access"),
} as const;
const GitHubNormalizedProviderPlanSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    desired: GitHubDesiredOrganizationAccessSchema,
    kind: z.literal("executable"),
    operations: z.array(GitHubProvisioningOperationSchema).readonly(),
  }),
  z.strictObject({
    blockers: z
      .tuple([GitHubProvisioningBlockerSchema])
      .rest(GitHubProvisioningBlockerSchema),
    desired: GitHubDesiredOrganizationAccessSchema,
    kind: z.literal("blocked"),
  }),
]);
const GitHubManagedAccountPlanSchema = z.strictObject({
  googleUserId: z.string().trim().min(1),
  plan: GitHubNormalizedProviderPlanSchema,
});
const GitHubSelectedOperationSchema = z.strictObject({
  desired: GitHubDesiredOrganizationAccessSchema,
  googleUserId: z.string().trim().min(1),
  operation: GitHubProvisioningOperationSchema,
});
export const GitHubAccessBranchPlanSchema = z
  .discriminatedUnion("execution", [
    z.strictObject({
      ...GITHUB_ACCESS_BRANCH_BASE,
      accountPlans: z.array(GitHubManagedAccountPlanSchema),
      authorityHash: Sha256Schema,
      contentHash: Sha256Schema,
      execution: z.literal("managed"),
      killSwitchEngaged: z.literal(false),
      managedTeamSlugs: z.array(z.string().trim().min(1)).readonly(),
      organizationId: z.string().regex(/^[1-9]\d*$/u),
      organizationLogin: z.string().trim().min(1),
      selectedOperation: GitHubSelectedOperationSchema.nullable(),
      teamAccessHash: Sha256Schema,
    }),
    z.strictObject({
      ...GITHUB_ACCESS_BRANCH_BASE,
      contentHash: z.string().regex(/^[a-f0-9]{64}$/u),
      execution: z.literal("audit-only"),
      killSwitchEngaged: z.literal(true),
      proposedChanges: GithubAccessAuditReportSchema.shape.proposedChanges,
    }),
    z.strictObject({
      ...GITHUB_ACCESS_BRANCH_BASE,
      contentHash: z.null(),
      execution: z.literal("disabled"),
      killSwitchEngaged: z.literal(true),
      proposedChanges: z.tuple([]),
    }),
  ])
  .superRefine((branch, context) => {
    if (branch.execution !== "managed" || branch.selectedOperation === null)
      return;
    const selected = branch.selectedOperation;
    const account = branch.accountPlans.find(
      (candidate) => candidate.googleUserId === selected.googleUserId,
    );
    if (
      account?.plan.kind !== "executable" ||
      !dequal(account.plan.desired, selected.desired) ||
      !dequal(account.plan.operations[0], selected.operation)
    ) {
      context.addIssue({
        code: "custom",
        message:
          "selected GitHub operation must be first in an executable account plan",
      });
    }
  });

const ACCESS_GUARD_BRANCH_BASE = {
  ...BRANCH_BASE,
  branchId: z.literal("access-guard"),
} as const;
export const AccessGuardBranchPlanSchema = z
  .discriminatedUnion("execution", [
    z.strictObject({
      ...ACCESS_GUARD_BRANCH_BASE,
      execution: z.literal("managed"),
      killSwitchEngaged: z.literal(false),
      plan: AccessGuardPlanSchema,
      reviewedLinearSuspension: ReviewedLinearSuspensionSchema.optional(),
      scheduledLinearSuspension: z.literal(true).optional(),
    }),
    z.strictObject({
      ...ACCESS_GUARD_BRANCH_BASE,
      execution: z.literal("disabled"),
      killSwitchEngaged: z.literal(true),
      plan: z.null(),
    }),
  ])
  .superRefine((branch, context) => {
    if (
      branch.execution !== "managed" ||
      branch.scheduledLinearSuspension !== true
    )
      return;
    if (
      branch.reviewedLinearSuspension !== undefined ||
      branch.plan.actions.length > 1
    )
      context.addIssue({
        code: "custom",
        message:
          "Scheduled Linear suspension requires a distinct single-identity selection",
      });
  });

export const IdentityProvisioningBranchPlanSchema = z.strictObject({
  ...BRANCH_BASE,
  branchId: z.literal("identity-provisioning"),
  execution: z.literal("managed"),
  githubIdentitySeed: GoogleGitHubIdentitySeedPlanSchema,
  killSwitchEngaged: z.literal(false),
  providerExecution: z.literal("audit-only"),
  schemaPlan: z.union([
    SarjIdentitySchemaPlanSchema,
    z.strictObject({ kind: z.literal("not-selected") }),
  ]),
  subjects: z.array(
    z.strictObject({
      authorityRevision: z.string().min(1),
      githubLinked: z.boolean(),
      googleUserId: z.string().min(1),
      lifecycle: GoogleLifecycleSchema,
    }),
  ),
});

const TRYCOMP_PEOPLE_BRANCH_BASE = {
  ...BRANCH_BASE,
  branchId: z.literal("trycomp-people"),
} as const;
export const TrycompPeopleBranchPlanSchema = z.discriminatedUnion("execution", [
  z.strictObject({
    ...TRYCOMP_PEOPLE_BRANCH_BASE,
    execution: z.literal("managed"),
    killSwitchEngaged: z.literal(false),
    reviewedPlan: TrycompReviewedPlanSchema,
  }),
  z.strictObject({
    ...TRYCOMP_PEOPLE_BRANCH_BASE,
    execution: z.literal("audit-only"),
    killSwitchEngaged: z.literal(true),
    reviewedPlan: TrycompReviewedPlanSchema,
  }),
  z.strictObject({
    ...TRYCOMP_PEOPLE_BRANCH_BASE,
    execution: z.literal("disabled"),
    killSwitchEngaged: z.literal(true),
    reviewedPlan: z.null(),
  }),
]);

export const SlackNamesBranchPlanSchema = z.strictObject({
  ...BRANCH_BASE,
  branchId: z.literal("slack-names"),
  execution: z.literal("managed"),
  killSwitchEngaged: z.literal(false),
  reviewed: ReviewedSlackNameActionSchema.nullable(),
  sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
});
export const LinearProfilesBranchPlanSchema = z.strictObject({
  ...BRANCH_BASE,
  branchId: z.literal("linear-profiles"),
  execution: z.literal("managed"),
  killSwitchEngaged: z.literal(false),
  reviewed: ReviewedLinearProfileActionSchema.nullable(),
  sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
});

export const GoogleGroupCleanupBranchPlanSchema = z
  .strictObject({
    ...BRANCH_BASE,
    branchId: z.literal("google-group-cleanup"),
    execution: BranchExecutionSchema,
    reviewed: ReviewedGoogleGroupCleanupSchema.nullable(),
    sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .refine(
    (branch) => branch.killSwitchEngaged === (branch.execution !== "managed"),
    "cleanup kill switch must match execution",
  );

export const PagerDutyTeamsBranchPlanSchema = z
  .strictObject({
    ...BRANCH_BASE,
    branchId: z.literal("pagerduty-teams"),
    execution: BranchExecutionSchema,
    reviewed: ReviewedPagerDutyTeamSchema.nullable(),
    sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .refine(
    (branch) => branch.killSwitchEngaged === (branch.execution !== "managed"),
    "PagerDuty kill switch must match execution",
  );

export const SentryMembershipsBranchPlanSchema = z
  .strictObject({
    ...BRANCH_BASE,
    branchId: z.literal("sentry-memberships"),
    execution: BranchExecutionSchema,
    reviewed: ReviewedSentryWorkspaceSchema.nullable(),
    sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .refine(
    (branch) => branch.killSwitchEngaged === (branch.execution !== "managed"),
    "Sentry kill switch must match execution",
  );

export const WorkspaceDirectoryBranchPlanSchema = z.discriminatedUnion(
  "branchId",
  [
    PagerDutyTeamsBranchPlanSchema,
    SentryMembershipsBranchPlanSchema,
    SlackProfilesBranchPlanSchema,
    DriveOrgChartBranchPlanSchema,
    SlackGroupsChannelsBranchPlanSchema,
    GitHubAccessBranchPlanSchema,
    AccessGuardBranchPlanSchema,
    IdentityProvisioningBranchPlanSchema,
    TrycompPeopleBranchPlanSchema,
    SlackNamesBranchPlanSchema,
    LinearProfilesBranchPlanSchema,
    GoogleGroupCleanupBranchPlanSchema,
  ],
);
export type WorkspaceDirectoryBranchPlan = z.output<
  typeof WorkspaceDirectoryBranchPlanSchema
>;

export const WorkspaceDirectoryPlanSchema = z
  .strictObject({
    authorityFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
    branches: z
      .tuple([
        SlackProfilesBranchPlanSchema,
        DriveOrgChartBranchPlanSchema,
        SlackGroupsChannelsBranchPlanSchema,
        GitHubAccessBranchPlanSchema,
        AccessGuardBranchPlanSchema,
        IdentityProvisioningBranchPlanSchema,
      ])
      .rest(
        z.union([
          TrycompPeopleBranchPlanSchema,
          SlackNamesBranchPlanSchema,
          LinearProfilesBranchPlanSchema,
          GoogleGroupCleanupBranchPlanSchema,
          PagerDutyTeamsBranchPlanSchema,
          SentryMembershipsBranchPlanSchema,
        ]),
      )
      .refine(
        (branches) =>
          new Set(branches.map(({ branchId }) => branchId)).size ===
          branches.length,
        "optional workspace branches must be unique",
      ),
    googleUsers: z.number().int().nonnegative(),
    policyVersion: z.enum([
      "workspace-directory-v10",
      WORKSPACE_DIRECTORY_FLOW.policyVersion,
    ]),
  })
  .refine(
    (plan) =>
      plan.policyVersion !== "workspace-directory-v10" ||
      plan.branches.every(
        ({ branchId }) =>
          branchId !== "slack-names" &&
          branchId !== "linear-profiles" &&
          branchId !== "google-group-cleanup" &&
          branchId !== "pagerduty-teams" &&
          branchId !== "sentry-memberships",
      ),
    "legacy workspace policy cannot authorize new name branches",
  );
export type WorkspaceDirectoryPlan = z.output<
  typeof WorkspaceDirectoryPlanSchema
>;

function validPagerDutySelection(plan: WorkspaceDirectoryPlan): boolean {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "pagerduty-teams",
  );
  return (
    branch?.execution === "managed" &&
    branch.reviewed !== null &&
    branch.sourceFingerprint === plan.authorityFingerprint &&
    !branch.diagnostics.some(({ severity }) => severity === "blocker")
  );
}

function validSentrySelection(plan: WorkspaceDirectoryPlan): boolean {
  const branch = plan.branches.find(
    (candidate) => candidate.branchId === "sentry-memberships",
  );
  return (
    branch?.execution === "managed" &&
    branch.reviewed !== null &&
    branch.sourceFingerprint === plan.authorityFingerprint &&
    !branch.diagnostics.some(({ severity }) => severity === "blocker")
  );
}

type PlannedChangeKind =
  | "pagerduty-teams"
  | "sentry-memberships"
  | "google-group-cleanup"
  | "slack-names"
  | "linear-profiles"
  | "trycomp-people"
  | "fanout"
  | "drive-org-chart"
  | "github-access"
  | "slack-groups-channels"
  | "slack-profiles";
export type WorkspaceDirectoryChangeDetails =
  | {
      [Kind in PlannedChangeKind]: { kind: Kind; plan: WorkspaceDirectoryPlan };
    }[PlannedChangeKind]
  | {
      kind: "linear-suspensions";
      actions: z.output<typeof AccessGuardPlanSchema>["actions"];
      plan?: WorkspaceDirectoryPlan | undefined;
    };
// Preserve the complete validated plan type without repeating its schema tree in every branch declaration.
const StoredWorkspaceDirectoryPlanSchema: z.ZodType<
  WorkspaceDirectoryPlan,
  z.input<typeof WorkspaceDirectoryPlanSchema>
> = WorkspaceDirectoryPlanSchema;
export const WorkspaceDirectoryChangeDetailsSchema: z.ZodType<WorkspaceDirectoryChangeDetails> =
  z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("pagerduty-teams"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("sentry-memberships"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("google-group-cleanup"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("slack-names"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("linear-profiles"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("trycomp-people"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("fanout"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("drive-org-chart"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("github-access"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      actions: AccessGuardPlanSchema.shape.actions,
      kind: z.literal("linear-suspensions"),
      plan: StoredWorkspaceDirectoryPlanSchema.optional(),
    }),
    z.strictObject({
      kind: z.literal("slack-groups-channels"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
    z.strictObject({
      kind: z.literal("slack-profiles"),
      plan: StoredWorkspaceDirectoryPlanSchema,
    }),
  ]);
const WorkspaceDirectoryAutomaticInputSchema = z
  .strictObject({
    includedActionIds: z
      .array(WorkspaceDirectoryAuthorizedActionIdSchema)
      .max(Object.keys(WORKSPACE_DIRECTORY_ACTION_IDS).length)
      .nullable()
      .default(null),
  })
  .default({ includedActionIds: null });

export const WorkspaceDirectoryOperationInputSchema = z.union([
  WorkspaceDirectoryAutomaticInputSchema,
  z.strictObject({
    includedActionIds: z.tuple([
      z.literal(WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels),
    ]),
    reviewedSlackLifecycleRemoval: ReviewedSlackLifecycleRemovalSchema,
  }),
  z.strictObject({
    includedActionIds: z.tuple([
      z.literal(WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions),
    ]),
    reviewedLinearSuspension: ReviewedLinearSuspensionSchema,
  }),
  z.strictObject({
    includedActionIds: z.tuple([
      z.literal(WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup),
    ]),
    reviewedGoogleGroupCleanup: ReviewedGoogleGroupCleanupIntentSchema,
  }),
]);

function isExactReviewedGroupRemoval(
  group: undefined | z.output<typeof SelectedSlackUserGroupReviewSchema>,
  reviewed: z.output<typeof ReviewedSlackLifecycleRemovalSchema>,
) {
  return (
    group?.slackUserGroupId === reviewed.slackUserGroupId &&
    group.memberRemovalAuthority === "explicit_google_lifecycle" &&
    group.memberRemovals.length === 1 &&
    group.memberRemovals[0]?.slackUserId === reviewed.slackUserId &&
    [
      group.memberAdditions,
      group.effectiveAccessAdditions,
      group.channelAdditions,
      group.channelRemovals,
    ].every((items) => items.length === 0)
  );
}

export const WorkspaceDirectoryWorkflowParamsSchema = z
  .strictObject({
    reviewedSlackLifecycleIntent:
      ClaimedReviewedSlackLifecycleIntentSchema.optional(),
    reviewedProviderIntent: ClaimedReviewedProviderIntentSchema.optional(),
    authorizedActionIds: z
      .array(WorkspaceDirectoryAuthorizedActionIdSchema)
      .max(Object.keys(WORKSPACE_DIRECTORY_ACTION_IDS).length)
      .refine(
        (ids) => new Set(ids).size === ids.length,
        "authorized action ids must be unique",
      ),
    requestedBy: z.string().trim().min(1).max(200),
    scheduledTickId: z
      .string()
      .regex(/^[a-f0-9]{64}$/u)
      .optional(),
    planGeneratedAt: z.iso.datetime({ offset: true }),
    plan: WorkspaceDirectoryPlanSchema,
    planHash: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .superRefine((params, context) => {
    const branch = params.plan.branches[4];
    if (
      branch.execution !== "managed" ||
      branch.scheduledLinearSuspension !== true ||
      !params.authorizedActionIds.includes(
        WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions,
      )
    )
      return;
    if (
      params.requestedBy !== "scheduled:workspace-directory" ||
      params.scheduledTickId === undefined ||
      params.reviewedProviderIntent !== undefined ||
      branch.plan.actions.length !== 1
    )
      context.addIssue({
        code: "custom",
        message:
          "Automatic Linear suspension requires scheduler parent authority without reviewed intent",
      });
  })
  .superRefine((params, context) => {
    if (
      params.authorizedActionIds.includes(
        WORKSPACE_DIRECTORY_ACTION_IDS.pagerDutyTeams,
      ) &&
      !validPagerDutySelection(params.plan)
    )
      context.addIssue({
        code: "custom",
        message:
          "PagerDuty requires one original managed reviewed action and matching Google authority",
      });
  })
  .superRefine((params, context) => {
    const intent = params.reviewedProviderIntent;
    if (
      intent !== undefined &&
      "provider" in intent.proof &&
      intent.proof.provider === "google-group-cleanup"
    )
      return;
    const branch = params.plan.branches[4];
    const reviewed =
      branch.execution === "managed"
        ? branch.reviewedLinearSuspension
        : undefined;
    if (intent === undefined && reviewed === undefined) return;
    if (
      intent === undefined ||
      reviewed === undefined ||
      !("provider" in intent.proof) ||
      params.reviewedSlackLifecycleIntent !== undefined ||
      params.requestedBy !== "scheduled:workspace-directory" ||
      params.scheduledTickId !== intent.claimedTickId ||
      params.authorizedActionIds.length !== 1 ||
      params.authorizedActionIds[0] !==
        WORKSPACE_DIRECTORY_ACTION_IDS.linearSuspensions ||
      !isReviewedPlanWithinOriginalApproval(
        intent.proof,
        params.planGeneratedAt,
      ) ||
      !dequal(reviewed, intent.proof.reviewed)
    )
      context.addIssue({
        code: "custom",
        message:
          "reviewed Linear write requires exact original scheduled intent and expiry",
      });
  })
  .superRefine((params, context) => {
    const intent = params.reviewedProviderIntent;
    if (
      intent === undefined ||
      !("provider" in intent.proof) ||
      intent.proof.provider !== "google-group-cleanup"
    )
      return;
    const branch = params.plan.branches.find(
      (candidate) => candidate.branchId === "google-group-cleanup",
    );
    if (
      branch?.execution !== "managed" ||
      branch.reviewed === null ||
      params.reviewedSlackLifecycleIntent !== undefined ||
      params.requestedBy !== "scheduled:workspace-directory" ||
      params.scheduledTickId !== intent.claimedTickId ||
      params.authorizedActionIds.length !== 1 ||
      params.authorizedActionIds[0] !==
        WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup ||
      !isReviewedPlanWithinOriginalApproval(
        intent.proof,
        params.planGeneratedAt,
      ) ||
      !dequal(branch.reviewed, intent.proof.reviewed)
    )
      context.addIssue({
        code: "custom",
        message:
          "reviewed Google cleanup requires exact original scheduled intent and expiry",
      });
  })
  .superRefine((params, context) => {
    const intent = params.reviewedSlackLifecycleIntent;
    const branch = params.plan.branches[2];
    const reviewed =
      branch.execution === "managed"
        ? branch.reviewedLifecycleRemoval
        : undefined;
    if (intent === undefined && reviewed === undefined) return;
    if (
      intent === undefined ||
      reviewed === undefined ||
      params.requestedBy !== "scheduled:workspace-directory" ||
      params.scheduledTickId !== intent.claimedTickId ||
      params.authorizedActionIds.length !== 1 ||
      params.authorizedActionIds[0] !==
        WORKSPACE_DIRECTORY_ACTION_IDS.slackGroupsChannels ||
      !isReviewedPlanWithinOriginalApproval(
        intent.proof,
        params.planGeneratedAt,
      ) ||
      reviewed.googleUserId !== intent.proof.reviewed.googleUserId ||
      reviewed.slackUserId !== intent.proof.reviewed.slackUserId ||
      reviewed.slackUserGroupId !== intent.proof.reviewed.slackUserGroupId
    )
      context.addIssue({
        code: "custom",
        message:
          "reviewed lifecycle write requires the exact original scheduled claim and expiry",
      });
  })
  .superRefine((params, context) => {
    if (
      params.authorizedActionIds.includes(
        WORKSPACE_DIRECTORY_ACTION_IDS.sentryMemberships,
      ) &&
      !validSentrySelection(params.plan)
    )
      context.addIssue({
        code: "custom",
        message:
          "Sentry requires one original managed reviewed action and matching Google authority",
      });
  })
  .superRefine((params, context) => {
    for (const branchId of ["slack-names", "linear-profiles"] as const) {
      if (
        !params.authorizedActionIds.includes(`workspace-directory.${branchId}`)
      )
        continue;
      const branch = params.plan.branches.find(
        (candidate) => candidate.branchId === branchId,
      );
      if (
        (branch?.branchId !== "slack-names" &&
          branch?.branchId !== "linear-profiles") ||
        branch.reviewed?.sourceFingerprint !== branch.sourceFingerprint ||
        params.scheduledTickId === undefined ||
        params.requestedBy !== "scheduled:workspace-directory"
      ) {
        context.addIssue({
          code: "custom",
          message:
            "authorized name action requires an exact scheduled parent branch",
          path: ["authorizedActionIds"],
        });
      }
    }
    if (
      params.scheduledTickId !== undefined &&
      params.requestedBy !== "scheduled:workspace-directory"
    ) {
      context.addIssue({
        code: "custom",
        message: "scheduled tick requires the trusted scheduled actor",
        path: ["scheduledTickId"],
      });
    }
    if (
      params.authorizedActionIds.includes(
        WORKSPACE_DIRECTORY_ACTION_IDS.googleGroupCleanup,
      )
    ) {
      const cleanup = params.plan.branches.find(
        (candidate) => candidate.branchId === "google-group-cleanup",
      );
      if (
        cleanup?.execution !== "managed" ||
        cleanup.reviewed === null ||
        cleanup.sourceFingerprint !== params.plan.authorityFingerprint
      )
        context.addIssue({
          code: "custom",
          message:
            "authorized cleanup requires original managed Google membership",
          path: ["authorizedActionIds"],
        });
    }
    if (
      !params.authorizedActionIds.includes(
        WORKSPACE_DIRECTORY_ACTION_IDS.trycompPeople,
      )
    )
      return;
    const branch = params.plan.branches.find(
      ({ branchId }) => branchId === "trycomp-people",
    );
    if (branch?.execution !== "managed") {
      context.addIssue({
        code: "custom",
        message: "authorized Trycomp action requires a managed Trycomp branch",
        path: ["authorizedActionIds"],
      });
    }
  });
export type WorkspaceDirectoryWorkflowParams = z.output<
  typeof WorkspaceDirectoryWorkflowParamsSchema
>;

const WORKFLOW_BRANCH_RESULT_BASE = {
  detail: z.string().min(1),
} as const;
const managedWorkflowResult = (branchId: WorkspaceDirectoryBranchId) =>
  z.strictObject({
    ...WORKFLOW_BRANCH_RESULT_BASE,
    branchId: z.literal(branchId),
    execution: z.literal("managed"),
    state: ManagedWorkflowStateSchema,
  });
const auditedWorkflowResult = (branchId: WorkspaceDirectoryBranchId) =>
  z.strictObject({
    ...WORKFLOW_BRANCH_RESULT_BASE,
    branchId: z.literal(branchId),
    execution: z.literal("audit-only"),
    state: z.literal("audited"),
  });
const disabledWorkflowResult = (branchId: WorkspaceDirectoryBranchId) =>
  z.strictObject({
    ...WORKFLOW_BRANCH_RESULT_BASE,
    branchId: z.literal(branchId),
    execution: z.literal("disabled"),
    state: z.literal("disabled"),
  });
const WorkspaceDirectoryWorkflowBranchResultSchema = z.union([
  auditedWorkflowResult("slack-profiles"),
  managedWorkflowResult("slack-profiles"),
  disabledWorkflowResult("slack-profiles"),
  managedWorkflowResult("drive-org-chart"),
  disabledWorkflowResult("drive-org-chart"),
  managedWorkflowResult("slack-groups-channels"),
  auditedWorkflowResult("slack-groups-channels"),
  disabledWorkflowResult("slack-groups-channels"),
  auditedWorkflowResult("github-access"),
  managedWorkflowResult("github-access"),
  disabledWorkflowResult("github-access"),
  managedWorkflowResult("access-guard"),
  disabledWorkflowResult("access-guard"),
  managedWorkflowResult("identity-provisioning"),
  managedWorkflowResult("trycomp-people"),
  managedWorkflowResult("slack-names"),
  managedWorkflowResult("linear-profiles"),
  managedWorkflowResult("google-group-cleanup"),
  managedWorkflowResult("pagerduty-teams"),
  auditedWorkflowResult("pagerduty-teams"),
  disabledWorkflowResult("pagerduty-teams"),
  managedWorkflowResult("sentry-memberships"),
  auditedWorkflowResult("sentry-memberships"),
  disabledWorkflowResult("sentry-memberships"),
  auditedWorkflowResult("google-group-cleanup"),
  disabledWorkflowResult("google-group-cleanup"),
  auditedWorkflowResult("trycomp-people"),
  disabledWorkflowResult("trycomp-people"),
]);

export const WorkspaceDirectoryWorkflowResultSchema = z.strictObject({
  authorizedActionIds: z
    .array(WorkspaceDirectoryAuthorizedActionIdSchema)
    .max(Object.keys(WORKSPACE_DIRECTORY_ACTION_IDS).length)
    .refine(
      (ids) => new Set(ids).size === ids.length,
      "authorized action ids must be unique",
    ),
  branches: z.array(WorkspaceDirectoryWorkflowBranchResultSchema),
  executionId: z.string().regex(/^[a-f0-9]{64}$/u),
  planHash: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type WorkspaceDirectoryWorkflowResult = z.output<
  typeof WorkspaceDirectoryWorkflowResultSchema
>;
