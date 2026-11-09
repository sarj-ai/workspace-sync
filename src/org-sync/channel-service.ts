import {
  buildEmployeeEntitlementAuthority,
  contractorAuthorityGroup,
  isEmployeeEntitlementExcluded,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import {
  type ResourceLeaseRepository,
  SLACK_USER_GROUPS_RESOURCE_LEASE_KEY,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import { sha256 } from "../runtime/sha256.ts";
import { logEvent } from "../shared/log-event.ts";
import {
  assertReviewedLifecycleIdentity,
  type LifecycleRemovalEvidence,
} from "./assert-reviewed-lifecycle-removal.ts";
import type {
  ChannelMembershipObservation,
  ChannelMembershipProvenanceRepository,
  ChannelMembershipProvenanceSource,
  ChannelMembershipRemovalCandidate,
  ChannelMembershipRemovalPlan,
} from "./channel-membership-provenance.ts";
import {
  removeProvenanceQualifiedChannelMemberships,
  selectProvenanceCaptureChannelIds,
} from "./channel-membership-provenance.ts";
import {
  type AllTeamPolicy,
  buildOrgChannelPlan,
  type ChannelMembershipChange,
  type ChannelRenameChange,
  deriveExcludedGoogleGroupEmails,
  type ManagedTeamPolicy,
  type OrgChannelPlan,
  type SlackChannelIdentity,
  type SlackChannelSyncSnapshot,
  type SlackUserGroupReconciliation,
  type SlackUserGroupSnapshot,
} from "./channel-model.ts";
import {
  assertUnprivilegedSlackMembershipIdentities,
  createSlackMembershipBudgetGuard,
  resolveSlackMembershipIdentities,
} from "./create-slack-membership-budget-guard.ts";
import { flattenGoogleGroups } from "./flatten-google-groups.ts";
import { mergeGoogleDirectoryAuthority } from "./google-directory-authority.ts";
import type { IGoogleDirectoryClient } from "./google-directory-client.ts";
import type { IGoogleGroupsClient } from "./google-groups-client.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
  type SlackMember,
} from "./model.ts";
import type {
  IOrgChannelSlackClient,
  SlackMembershipFinalSourceAuthority,
} from "./org-channel-slack-client.ts";
import {
  createReviewedSlackLifecycleFinalGuard,
  type ReviewedSlackLifecycleParentContext,
  type ReviewedSlackLifecycleRemoval,
  selectReviewedSlackLifecycleRemoval,
} from "./reviewed-lifecycle-removal.ts";
import { SlackWriteOutcomeUnknownError } from "./slack-api-transport.ts";

const REQUIRED_SLACK_READ_SCOPES = [
  "channels:read",
  "groups:read",
  "users:read",
  "users:read.email",
] as const;
const MAX_RUN_MS = 8 * 60 * 1000;
const MEMBERSHIP_IDENTITY_INVALID =
  "slack_membership_identity_authority_invalid";
const WRITE_SAFETY_MARGIN_MS = 30_000;
const LEASE_POST_DEADLINE_FENCE_MS = 30_000;
const PROVIDER_READBACK_DEADLINE_MS = 60_000;
const USER_GROUP_SELECTION_POLICY_VERSION = "risk_v12";
const MAX_IDENTITIES_PER_USER_GROUP_WRITE = 1;
const SLACK_USER_GROUP_OWNERSHIP_RANK = {
  "explicitly_adopted": 0,
  "automation_created": 1,
  "automation_bootstrap": 2,
  "legacy_unmanaged": 3,
} as const;

export interface OrgChannelSyncConfig {
  allowedPublicChannelNames: string[];
  allowedPublicChannelPrefixes: string[];
  allTeam?: AllTeamPolicy;
  assignmentGroupEmails: string[];
  automaticMemberRemovalScope:
    | { readonly kind: "all_managed" }
    | {
        readonly kind: "immutable_ids";
        readonly slackUserGroupIds: readonly string[];
      }
    | { readonly kind: "none" };
  contractorOnlyMemberRemovals?: boolean;
  expectedSlackTeamId: string;
  managedTeams: ManagedTeamPolicy[];
  maxAutomaticAdditions: number;
  maxAutomaticChannelInvites: number;
  maxAutomaticChannelMembershipRemovals?: number;
  maxAutomaticChannelRenames?: number;
  maxAutomaticContractorRemovals?: number;
  maxAutomaticGoogleGroupRemovals?: number;
  maxAutomaticRemovals: number;
  maxAutomaticUserGroupChanges?: number;
  minimumActiveGoogleUsers: number;
  protectedSlackUserIds?: readonly string[];
  requiredPrivateChannelNames?: string[];
  requireRemovalPlanHash?: boolean;
}

export interface OrgChannelSyncRunOptions {
  allowRemovals: boolean;
  expectedPlanHash?: string | undefined;
  googleUsers?: readonly GoogleDirectoryUser[] | undefined;
  identityBudget?: IdentityWriteBudget | undefined;
  mode: "audit" | "live";
  requireUnprivilegedIdentity?: boolean;
  reviewedLifecycleParent?: ReviewedSlackLifecycleParentContext;
  reviewedLifecycleRemoval?: ReviewedSlackLifecycleRemoval;
  trigger: "cron" | "http";
}

export interface OrgChannelSyncRunReport {
  additions: ChannelMembershipChange[];
  channelRenames: ChannelRenameChange[];
  durationMs: number;
  errors: string[];
  lifecycle: OrgChannelPlan["lifecycle"];
  managerTargets: OrgChannelPlan["managerTargets"];
  planHash: string;
  provenanceChannelRemovalCandidates: ChannelMembershipRemovalCandidate[];
  removals: ChannelMembershipChange[];
  runId: string;
  selectedChannelAdditions: ChannelMembershipChange[];
  selectedChannelRename: ChannelRenameChange | null;
  selectedProvenanceChannelRemovals: ChannelMembershipRemovalPlan[];
  selectedUserGroupHandles: string[];
  selectedUserGroups: SlackUserGroupReconciliation[];
  selectionPolicyVersion: typeof USER_GROUP_SELECTION_POLICY_VERSION;
  status: "audit" | "blocked" | "failed" | "success";
  userGroups: OrgChannelPlan["userGroups"];
  warnings: string[];
  writes: number;
}

interface MembershipPlanReadInput {
  allowRemovals: boolean;
  googleUsers: readonly GoogleDirectoryUser[];
  reviewedLifecycleReadback?: ReviewedSlackLifecycleRemoval;
  reviewedLifecycleRemoval?: ReviewedSlackLifecycleRemoval;
  slackUserId: string;
}

export interface IOrgChannelSyncService {
  readChannelIdentity(channelId: string): Promise<SlackChannelIdentity>;
  readChannelMemberIds(channelId: string): Promise<readonly string[]>;
  readMembershipIdentities(
    slackUserIds: readonly string[],
    googleUsers: readonly GoogleDirectoryUser[],
  ): Promise<Map<string, string>>;
  readMembershipPlan(
    input: MembershipPlanReadInput,
  ): Promise<{ googleUserId: string; report: OrgChannelSyncRunReport }>;
  run(options: OrgChannelSyncRunOptions): Promise<OrgChannelSyncRunReport>;
}

export type OriginalSlackMembershipObservation = Pick<
  SlackChannelSyncSnapshot,
  "channels" | "inventory" | "userGroups"
> & { googleUserId: string; slackUserId: string; plan: OrgChannelPlan };

export interface IOrgChannelMembershipObservationReader {
  readOriginalMembershipObservation(input: {
    googleUsers: readonly GoogleDirectoryUser[];
    googleUserId: string;
    slackUserId: string;
  }): Promise<OriginalSlackMembershipObservation>;
}

export class OrgChannelSyncService
  implements IOrgChannelSyncService, IOrgChannelMembershipObservationReader
{
  readonly #config: OrgChannelSyncConfig;
  readonly #googleDirectory: IGoogleDirectoryClient;
  readonly #googleGroups: IGoogleGroupsClient;
  readonly #leaseRepository: ResourceLeaseRepository;
  readonly #provenanceRepository:
    | ChannelMembershipProvenanceRepository
    | undefined;
  readonly #slack: IOrgChannelSlackClient;

  constructor(
    config: OrgChannelSyncConfig,
    googleDirectory: IGoogleDirectoryClient,
    googleGroups: IGoogleGroupsClient,
    slack: IOrgChannelSlackClient,
    leaseRepository: ResourceLeaseRepository,
    provenanceRepository?: ChannelMembershipProvenanceRepository,
  ) {
    this.#config = config;
    this.#googleDirectory = googleDirectory;
    this.#googleGroups = googleGroups;
    this.#leaseRepository = leaseRepository;
    this.#provenanceRepository = provenanceRepository;
    this.#slack = slack;
  }

  async run(
    options: OrgChannelSyncRunOptions,
  ): Promise<OrgChannelSyncRunReport> {
    const startedAt = Date.now();
    const runId = crypto.randomUUID();
    const deadlineAt = startedAt + MAX_RUN_MS;
    try {
      return await this.#executeRun(options, runId, startedAt, deadlineAt);
    } catch (error) {
      const failure = toError(error);
      logEvent("org_channel_sync.completed", {
        "duration_ms": Date.now() - startedAt,
        error: failure.message,
        "run_id": runId,
        status: "failed",
        writes: 0,
      });
      throw failure;
    }
  }

  async readChannelIdentity(channelId: string): Promise<SlackChannelIdentity> {
    const startedAt = Date.now();
    return this.#slack.getChannelIdentity(
      channelId,
      crypto.randomUUID(),
      startedAt + PROVIDER_READBACK_DEADLINE_MS,
    );
  }

  async readMembershipIdentities(
    slackUserIds: readonly string[],
    googleUsers: readonly GoogleDirectoryUser[],
  ): Promise<Map<string, string>> {
    const snapshot = await this.#buildPlan(
      crypto.randomUUID(),
      Date.now() + MAX_RUN_MS,
      googleUsers,
    );
    if (snapshot.plan.errors.length > 0)
      throw new Error(MEMBERSHIP_IDENTITY_INVALID);
    return assertUnprivilegedSlackMembershipIdentities(
      snapshot,
      slackUserIds,
      this.#config.protectedSlackUserIds,
    );
  }

  async readMembershipPlan(
    input: MembershipPlanReadInput,
  ): Promise<{ googleUserId: string; report: OrgChannelSyncRunReport }> {
    const startedAt = Date.now();
    const runId = crypto.randomUUID();
    const deadlineAt = startedAt + MAX_RUN_MS;
    const snapshot = await this.#buildPlan(
      runId,
      deadlineAt,
      input.googleUsers,
    );
    if (snapshot.plan.errors.length > 0)
      throw new Error(MEMBERSHIP_IDENTITY_INVALID);
    const identities = assertUnprivilegedSlackMembershipIdentities(
      snapshot,
      [input.slackUserId],
      this.#config.protectedSlackUserIds,
    );
    const googleUserId = identities.get(input.slackUserId);
    if (googleUserId === undefined)
      throw new Error(MEMBERSHIP_IDENTITY_INVALID);
    const reviewed = input.reviewedLifecycleReadback;
    if (
      reviewed !== undefined &&
      (reviewed.slackUserId !== input.slackUserId ||
        reviewed.googleUserId !== googleUserId)
    )
      throw new Error("reviewed_lifecycle_identity_changed");
    const evidence =
      reviewed === undefined
        ? undefined
        : await this.#captureLifecycleEvidence(runId, deadlineAt);
    if (reviewed !== undefined && evidence !== undefined) {
      const user = assertReviewedLifecycleIdentity(reviewed, evidence);
      if (
        user.suspended !== true ||
        user.archived === true ||
        user.deletionTime !== undefined
      )
        throw new Error("reviewed_lifecycle_suspended_authority_required");
    }
    const pendingReview =
      reviewed !== undefined &&
      snapshot.plan.userGroups.some(
        (group) =>
          group.slackUserGroupId === reviewed.slackUserGroupId &&
          group.memberRemovals.some(
            ({ slackUserId }) => slackUserId === reviewed.slackUserId,
          ),
      )
        ? reviewed
        : input.reviewedLifecycleRemoval;
    const report = await this.#executeSnapshot(
      {
        allowRemovals: input.allowRemovals,
        googleUsers: input.googleUsers,
        ...(!(pendingReview === undefined) && {
          reviewedLifecycleRemoval: pendingReview,
        }),
        mode: "audit",
        trigger: "http",
      },
      runId,
      startedAt,
      deadlineAt,
      snapshot,
      evidence,
    );
    return { googleUserId, report };
  }

  async readOriginalMembershipObservation(input: {
    googleUsers: readonly GoogleDirectoryUser[];
    googleUserId: string;
    slackUserId: string;
  }) {
    const snapshot = await this.#buildPlan(
      crypto.randomUUID(),
      Date.now() + PROVIDER_READBACK_DEADLINE_MS,
      input.googleUsers,
    );
    if (snapshot.plan.errors.length > 0)
      throw new Error(MEMBERSHIP_IDENTITY_INVALID);
    const identities = resolveSlackMembershipIdentities(snapshot, [
      input.slackUserId,
    ]);
    if (identities.get(input.slackUserId) !== input.googleUserId)
      throw new Error("workspace_slack_membership_identity_changed");
    return {
      googleUserId: input.googleUserId,
      slackUserId: input.slackUserId,
      userGroups: snapshot.observedUserGroups,
      channels: snapshot.observedChannels,
      inventory: snapshot.channels,
      plan: snapshot.plan,
    };
  }

  async readChannelMemberIds(channelId: string): Promise<readonly string[]> {
    const startedAt = Date.now();
    return this.#slack.listChannelMembers(
      channelId,
      crypto.randomUUID(),
      startedAt + PROVIDER_READBACK_DEADLINE_MS,
    );
  }

  async #executeRun(
    options: OrgChannelSyncRunOptions,
    runId: string,
    startedAt: number,
    deadlineAt: number,
  ): Promise<OrgChannelSyncRunReport> {
    const snapshot = await this.#buildPlan(
      runId,
      deadlineAt,
      options.googleUsers,
    );
    return this.#executeSnapshot(
      options,
      runId,
      startedAt,
      deadlineAt,
      snapshot,
    );
  }

  async #executeSnapshot(
    options: OrgChannelSyncRunOptions,
    runId: string,
    startedAt: number,
    deadlineAt: number,
    snapshot: SnapshotPlan,
    lifecycleEvidence?: LifecycleRemovalEvidence,
  ): Promise<OrgChannelSyncRunReport> {
    const { plan } = snapshot;
    let selectedUserGroups = await this.#selectReviewedOrAutomaticGroups(
      plan,
      options,
      runId,
      deadlineAt,
      lifecycleEvidence,
    );
    const contractorSlackUserIds = new Set(
      plan.lifecycle.allTeamProjection?.excludedFromSourceMembers.map(
        ({ slackUserId }) => slackUserId,
      ),
    );
    const protectedSlackUserIds = new Set(this.#config.protectedSlackUserIds);
    const {
      eligibleCandidates: eligibleProvenanceCandidates,
      repositoryCandidates: provenanceCandidates,
    } = await listEligibleProvenanceCandidates(
      this.#provenanceRepository,
      contractorSlackUserIds,
      protectedSlackUserIds,
      this.#config.contractorOnlyMemberRemovals === true,
    );
    const provenanceChannelRemovalCandidates = provenanceCandidates;
    const channelIdentityById = new Map(
      snapshot.channels.map((channel) => [channel.id, channel]),
    );
    let selectedProvenanceChannelRemovals =
      selectedUserGroups.length === 0
        ? eligibleProvenanceCandidates
            .flatMap((candidate) => {
              const channel = channelIdentityById.get(candidate.channelId);
              return channel && !channel.isArchived
                ? {
                    ...candidate,
                    channelName: channel.name,
                    isPrivate: channel.isPrivate,
                  }
                : [];
            })
            .slice(0, this.#config.maxAutomaticChannelMembershipRemovals ?? 0)
        : [];
    const selectedChannelAdditions = selectAutomaticChannelAdditions(
      plan,
      null,
      this.#config.maxAutomaticChannelInvites,
    );
    ({ selectedProvenanceChannelRemovals, selectedUserGroups } =
      isolateChannelInvitationWork(
        selectedChannelAdditions,
        selectedUserGroups,
        selectedProvenanceChannelRemovals,
      ));
    const selectedUserGroupHandles = selectedUserGroups.map(
      (group) => group.handle,
    );
    const selectedChannelRename =
      selectedChannelAdditions.length === 0 &&
      channelRenameSelectionAllowed(
        selectedUserGroupHandles,
        selectedProvenanceChannelRemovals,
      )
        ? selectChannelRenameForWrite(
            plan,
            snapshot.scopes,
            this.#config.maxAutomaticChannelRenames ?? 0,
          )
        : null;
    appendUserGroupSelectionWarnings(plan, this.#config, options.allowRemovals);
    appendProtectedAdditionWarnings(plan, this.#config.protectedSlackUserIds);
    appendSelectedContractorRemainderWarnings(
      plan,
      selectedUserGroups,
      this.#config,
    );
    appendSelectedAdditionRemainderWarnings(plan, selectedUserGroups);
    const planHash = await hashPlan(
      plan,
      selectedChannelAdditions,
      selectedUserGroups,
      selectedChannelRename,
      selectedProvenanceChannelRemovals,
    );
    logEvent("org_channel_sync.plan", {
      additions: plan.additions.length,
      "channel_renames": plan.channelRenames.length,
      errors: plan.errors.length,
      "manager_targets": plan.managerTargets.length,
      "plan_hash": planHash,
      removals: plan.removals.length,
      "run_id": runId,
      "selected_user_group_handles": selectedUserGroupHandles.join(","),
      "selection_policy_version": USER_GROUP_SELECTION_POLICY_VERSION,
      trigger: options.trigger,
      "user_group_changes": plan.userGroups.filter(
        (group) => group.status !== "in_sync",
      ).length,
      warnings: plan.warnings.length,
    });
    const report = (
      status: OrgChannelSyncRunReport["status"],
      writeCount = 0,
    ): OrgChannelSyncRunReport => ({
      ...plan,
      durationMs: Date.now() - startedAt,
      planHash,
      provenanceChannelRemovalCandidates,
      runId,
      selectedChannelAdditions,
      selectedChannelRename,
      selectedProvenanceChannelRemovals,
      selectedUserGroupHandles,
      selectedUserGroups,
      selectionPolicyVersion: USER_GROUP_SELECTION_POLICY_VERSION,
      status,
      writes: writeCount,
    });
    if (plan.errors.length > 0) return finishReport(report("failed"));
    if (options.mode === "audit") return finishReport(report("audit"));
    if (options.trigger !== "cron") {
      return finishReport(
        reportWithError(report("blocked"), "Live channel writes are cron-only"),
      );
    }
    const capabilityError = liveCapabilityError(
      plan,
      selectedChannelAdditions,
      selectedUserGroupHandles,
      selectedProvenanceChannelRemovals,
      snapshot.scopes,
      selectedChannelRename,
    );
    if (capabilityError)
      return finishReport(reportWithError(report("blocked"), capabilityError));
    const safetyError = liveSafetyError(
      plan,
      selectedChannelAdditions,
      selectedUserGroups,
      selectedProvenanceChannelRemovals,
      selectedChannelRename,
      options,
      this.#config,
      planHash,
    );
    if (safetyError)
      return finishReport(reportWithError(report("blocked"), safetyError));
    if (plan.removals.length > 0) {
      plan.warnings.push(
        `${String(plan.removals.length)} direct channel membership removals remain deferred because direct writes are disabled`,
      );
    }
    appendDeferredChangeWarnings(plan, this.#config, snapshot.scopes);

    if (!hasWriteBudget(deadlineAt)) {
      return finishReport(
        reportWithError(
          report("blocked"),
          "Safety stop: run deadline is too close for writes",
        ),
      );
    }
    const membershipGuard = createSlackMembershipBudgetGuard({
      authority: snapshot,
      budget: options.identityBudget,
      requireUnprivilegedIdentity:
        options.requireUnprivilegedIdentity === true ||
        options.reviewedLifecycleRemoval !== undefined,
      protectedSlackUserIds: this.#config.protectedSlackUserIds ?? [],
      refreshAuthority: () =>
        this.#refreshMembershipAuthority(
          runId,
          deadlineAt,
          selectedChannelAdditions,
          selectedUserGroups,
        ),
      slackUserIds: [
        ...selectedChannelAdditions.map(({ slackUserId }) => slackUserId),
        ...selectedUserGroups.flatMap((group) =>
          group.automationOwnership.kind === "automation_bootstrap"
            ? []
            : [
                ...group.memberAdditions.map(({ slackUserId }) => slackUserId),
                ...group.memberRemovals.map(({ slackUserId }) => slackUserId),
                ...group.effectiveAccessAdditions.map(
                  ({ slackUserId }) => slackUserId,
                ),
              ],
        ),
        ...selectedProvenanceChannelRemovals.map(
          ({ slackUserId }) => slackUserId,
        ),
      ],
    });
    const reviewedGuard = this.#reviewedLifecycleGuards(
      options,
      selectedUserGroups,
      runId,
      deadlineAt,
    );
    const applied = await this.#applyWithOverlapGuard(
      plan,
      selectedChannelRename,
      selectedChannelAdditions,
      selectedUserGroups,
      selectedProvenanceChannelRemovals,
      runId,
      deadlineAt,
      membershipGuard,
      reviewedGuard,
    );
    if (applied.error) {
      logEvent("org_channel_sync.apply_failed", {
        error: applied.error.message,
        "run_id": runId,
        writes: applied.writes,
      });
      return finishReport(
        reportWithError(
          report("failed", applied.writes),
          applied.error.message,
        ),
      );
    }
    return finishReport(report("success", applied.writes));
  }

  async #selectReviewedOrAutomaticGroups(
    plan: OrgChannelPlan,
    options: OrgChannelSyncRunOptions,
    runId: string,
    deadlineAt: number,
    lifecycleEvidence?: LifecycleRemovalEvidence,
  ) {
    if (options.reviewedLifecycleRemoval === undefined)
      return selectUserGroupsForWrite(
        plan,
        this.#config,
        options.allowRemovals,
      );
    return [
      selectReviewedSlackLifecycleRemoval(
        plan.userGroups,
        options.reviewedLifecycleRemoval,
        lifecycleEvidence ??
          (await this.#captureLifecycleEvidence(runId, deadlineAt)),
      ),
    ];
  }

  async #captureLifecycleEvidence(runId: string, deadlineAt: number) {
    const listUsers = this.#slack.listMembershipUsers?.bind(this.#slack);
    if (listUsers === undefined)
      throw new Error("reviewed_lifecycle_slack_source_reader_required");
    const groups = await this.#googleGroups.listGroups(
      [contractorAuthorityGroup().email],
      runId,
      deadlineAt,
    );
    const group = groups.length === 1 ? groups[0] : undefined;
    if (group === undefined)
      throw new Error("reviewed_lifecycle_contractor_source_required");
    const contractorAuthority = await buildEmployeeEntitlementAuthority(group);
    const slackMembers = await listUsers(runId, deadlineAt);
    const directoryUsers = await this.#captureGoogleAuthority(
      runId,
      deadlineAt,
    );
    return {
      contractorAuthority,
      directoryUsers,
      slackMembers,
      protectedSlackUserIds: this.#config.protectedSlackUserIds ?? [],
    };
  }

  #reviewedLifecycleGuards(
    options: OrgChannelSyncRunOptions,
    groups: readonly SlackUserGroupReconciliation[],
    runId: string,
    deadlineAt: number,
  ) {
    const reviewed = options.reviewedLifecycleRemoval;
    if (reviewed === undefined) return;
    const expected = groups.length === 1 ? groups[0] : undefined;
    const parent = options.reviewedLifecycleParent;
    if (expected === undefined || parent === undefined)
      throw new Error("reviewed_lifecycle_signed_parent_required");
    const beforeWrite = createReviewedSlackLifecycleFinalGuard({
      budget: options.identityBudget,
      parent,
      reviewed,
      expected,
      capture: async () => {
        const fresh = await this.#buildPlan(runId, deadlineAt);
        if (fresh.plan.errors.length > 0)
          throw new Error("reviewed_lifecycle_source_invalid");
        return {
          groups: fresh.plan.userGroups,
          evidence: await this.#captureLifecycleEvidence(runId, deadlineAt),
        };
      },
    });
    return {
      beforeWrite,
      finalSource: {
        assertFinalSourceAuthority: async () => {
          const evidence = await this.#captureLifecycleEvidence(
            runId,
            deadlineAt,
          );
          selectReviewedSlackLifecycleRemoval([expected], reviewed, evidence);
          await parent.assertFinalGoogleAuthority(evidence.directoryUsers);
          parent.assertFreshPlan();
        },
        assertFreshPlan: () => {
          parent.assertFreshPlan();
          ensureWriteBudget(deadlineAt);
        },
      },
    };
  }

  async #buildPlan(
    runId: string,
    deadlineAt: number,
    googleUsers?: readonly GoogleDirectoryUser[],
  ): Promise<SnapshotPlan> {
    const channelNames = this.#config.managedTeams.flatMap((team) => [
      team.privateChannel.name,
      team.legacyPrivateChannel.name,
      ...(team.additionalLegacyPrivateChannels ?? []).map(
        (channel) => channel.name,
      ),
      team.asksChannel.name,
      ...(team.legacyAsksChannels ?? []).map((channel) => channel.name),
      ...(team.additionalChannels ?? []).map((channel) => channel.name),
    ]);
    const requireUserGroups =
      this.#config.allTeam !== undefined ||
      this.#config.managedTeams.some(
        (team) => team.accessMode === "user_group",
      );
    const managedUserGroupHandles = this.#config.managedTeams.flatMap((team) =>
      team.accessMode === "user_group" &&
      team.projectionMode !== "assignment_only"
        ? [team.slackUserGroup.handle, ...team.slackUserGroup.legacyHandles]
        : [],
    );
    if (this.#config.allTeam) {
      managedUserGroupHandles.push(
        this.#config.allTeam.slackUserGroup.handle,
        ...this.#config.allTeam.slackUserGroup.legacyHandles,
      );
    }
    const [directoryUsers, slack] = await Promise.all([
      googleUsers ?? this.#captureGoogleAuthority(runId, deadlineAt),
      this.#slack.listSnapshot(
        channelNames,
        runId,
        deadlineAt,
        requireUserGroups,
        managedUserGroupHandles,
      ),
    ]);
    const projectedGroupEmails = this.#config.managedTeams.map(
      (team) => team.googleGroupEmail,
    );
    const excludedGroupEmails = deriveExcludedGoogleGroupEmails(
      this.#config.managedTeams,
      this.#config.allTeam,
    );
    const allRequiredGroupEmails = mergeUniqueStrings(
      this.#config.assignmentGroupEmails,
      [...projectedGroupEmails, ...excludedGroupEmails],
    );
    const allRequiredGroups = await this.#googleGroups.listGroups(
      allRequiredGroupEmails,
      runId,
      deadlineAt,
      true,
    );
    const flattenedRequiredGroups = flattenGoogleGroups(
      allRequiredGroupEmails,
      allRequiredGroups,
    );
    const assignmentGroupEmailSet = new Set(
      this.#config.assignmentGroupEmails.map(normalizeEmail),
    );
    const assignmentGroups = flattenedRequiredGroups.filter((group) =>
      assignmentGroupEmailSet.has(normalizeEmail(group.email)),
    );
    const googleGroupInventory = await this.#googleGroups.listAllGroups(
      runId,
      deadlineAt,
    );
    const managedGroupEmails = new Set(
      [
        ...this.#config.managedTeams.map((team) => team.googleGroupEmail),
        ...excludedGroupEmails,
      ].map(normalizeEmail),
    );
    const managedGroups = flattenedRequiredGroups.filter((group) =>
      managedGroupEmails.has(normalizeEmail(group.email)),
    );
    const activeGoogleUsers = directoryUsers.filter(
      isActiveGoogleDirectoryUser,
    );
    const plan = buildOrgChannelPlan({
      activeGoogleUsers,
      inactiveGoogleUsers: directoryUsers.filter(
        (user) => !isActiveGoogleDirectoryUser(user),
      ),
      ...(this.#config.allTeam && { allTeam: this.#config.allTeam }),
      allowedPublicChannelNames: this.#config.allowedPublicChannelNames,
      allowedPublicChannelPrefixes: this.#config.allowedPublicChannelPrefixes,
      assignmentGroupEmails: this.#config.assignmentGroupEmails,
      assignmentGroups,
      googleGroupInventory,
      managedGroups,
      managedTeams: this.#config.managedTeams,
      ...(this.#config.protectedSlackUserIds && {
        protectedSlackUserIds: this.#config.protectedSlackUserIds,
      }),
      ...(this.#config.requiredPrivateChannelNames && {
        requiredPrivateChannelNames: this.#config.requiredPrivateChannelNames,
      }),
      slack,
    });
    validateSnapshot(plan, {
      activeGoogleUsers: activeGoogleUsers.length,
      expectedSlackTeamId: this.#config.expectedSlackTeamId,
      minimumActiveGoogleUsers: this.#config.minimumActiveGoogleUsers,
      requireUserGroups,
      scopes: slack.scopes,
      teamId: slack.teamId,
    });
    return {
      channels: slack.inventory,
      observedChannels: slack.channels,
      observedUserGroups: slack.userGroups,
      plan,
      scopes: slack.scopes,
      directoryUsers,
      slackMembers: slack.members,
    };
  }

  async #captureGoogleAuthority(
    runId: string,
    deadlineAt: number,
  ): Promise<GoogleDirectoryUser[]> {
    const [activeUsers, deletedUsers] = await Promise.all([
      this.#googleDirectory.listAllUsers(runId, deadlineAt),
      this.#googleDirectory.listDeletedUsers?.(runId, deadlineAt) ??
        Promise.resolve([]),
    ]);
    return mergeGoogleDirectoryAuthority(activeUsers, deletedUsers);
  }

  async #refreshMembershipAuthority(
    runId: string,
    deadlineAt: number,
    selectedChannelAdditions: readonly ChannelMembershipChange[],
    selectedUserGroups: readonly SlackUserGroupReconciliation[],
  ): Promise<SnapshotPlan> {
    const fresh = await this.#buildPlan(runId, deadlineAt);
    if (fresh.plan.errors.length > 0)
      throw new Error("slack_budget_authority_invalid");
    const channelAuthorityChanged = selectedChannelAdditions.some(
      (expected) =>
        !fresh.plan.additions.some((current) =>
          sameChannelMembership(current, expected),
        ),
    );
    if (channelAuthorityChanged)
      throw new Error("slack_budget_channel_authority_changed");
    for (const selected of selectedUserGroups) {
      const current = fresh.plan.userGroups.find(
        ({ handle }) => handle === selected.handle,
      );
      if (!current || !sameUserGroupAuthority(current, selected)) {
        throw new Error("slack_budget_membership_authority_changed");
      }
      const affected = [
        ...selected.memberAdditions,
        ...selected.memberRemovals,
        ...selected.effectiveAccessAdditions,
        ...(selected.channelAdditions.length > 0
          ? plannedCurrentUserIds(selected).map((slackUserId) => ({
              slackUserId,
            }))
          : []),
      ];
      const membershipChanged = affected.some(
        ({ slackUserId }) =>
          current.desiredUserIds.includes(slackUserId) !==
          selected.desiredUserIds.includes(slackUserId),
      );
      if (membershipChanged)
        throw new Error("slack_budget_membership_authority_changed");
    }
    return fresh;
  }

  async #applyChanges(
    plan: OrgChannelPlan,
    selectedChannelRename: ChannelRenameChange | null,
    selectedChannelAdditions: readonly ChannelMembershipChange[],
    selectedUserGroups: readonly SlackUserGroupReconciliation[],
    selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<{ error: Error | null; writes: number }> {
    if (selectedChannelRename) {
      return this.#applySelectedRename(
        selectedChannelRename,
        runId,
        deadlineAt,
        assertLeaseActive,
      );
    }
    if (
      selectedUserGroups.length === 0 &&
      selectedProvenanceChannelRemovals.length === 0 &&
      selectedChannelAdditions.length === 0 &&
      plan.removals.length > 0
    ) {
      return {
        error: new Error(
          "Direct Slack channel membership writes are disabled; use Slack user groups",
        ),
        writes: 0,
      };
    }
    const userGroups = await this.#applySelectedUserGroups(
      selectedUserGroups,
      runId,
      deadlineAt,
      assertLeaseActive,
    );
    if (userGroups.error) return userGroups;
    const channelAdditions = await this.#applyDirectChannelAdditions(
      selectedChannelAdditions,
      runId,
      deadlineAt,
      assertLeaseActive,
    );
    if (channelAdditions.error) {
      return {
        error: channelAdditions.error,
        writes: userGroups.writes + channelAdditions.writes,
      };
    }
    const channelRemovals = await this.#applyProvenanceChannelRemovals(
      selectedProvenanceChannelRemovals,
      runId,
      deadlineAt,
      assertLeaseActive,
    );
    return {
      error: channelRemovals.error,
      writes:
        userGroups.writes + channelAdditions.writes + channelRemovals.writes,
    };
  }

  async #applyProvenanceChannelRemovals(
    candidates: readonly ChannelMembershipRemovalPlan[],
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<{ error: Error | null; writes: number }> {
    const limit = this.#config.maxAutomaticChannelMembershipRemovals ?? 0;
    if (limit === 0 || !this.#provenanceRepository)
      return { error: null, writes: 0 };
    if (!this.#slack.getChannelRemovalSafety || !this.#slack.kick) {
      return {
        error: new Error("Slack provenance removal capability is unavailable"),
        writes: 0,
      };
    }
    try {
      await assertLeaseActive();
      const allowedChannelIds = new Set(
        [this.#config.allTeam, ...this.#config.managedTeams].flatMap((policy) =>
          policy?.slackUserGroup.automationOwnership?.kind ===
          "legacy_unmanaged"
            ? []
            : (policy?.slackUserGroup.automationOwnership?.allowedChannelIds ??
              []),
        ),
      );
      const writes = await removeProvenanceQualifiedChannelMemberships({
        allowedChannelIds,
        assertNoRenewedSource: (candidate, sources) =>
          this.#assertNoRenewedProvenanceSource(
            candidate,
            sources,
            runId,
            deadlineAt,
          ),
        assertWriteAuthority: assertLeaseActive,
        ...(!(membershipCallbacks(assertLeaseActive)[0] === undefined) && {
          beforeMembershipMutation: membershipCallbacks(assertLeaseActive)[0],
        }),
        candidates,
        maxRemovals: limit,
        protectedSlackUserIds: new Set(this.#config.protectedSlackUserIds),
        repository: this.#provenanceRepository,
        runId,
        slack: {
          getChannelRemovalSafety: (channelId, currentRunId) =>
            this.#slack.getChannelRemovalSafety?.(
              channelId,
              currentRunId,
              deadlineAt,
            ) ??
            Promise.reject(
              new Error("Slack provenance removal capability is unavailable"),
            ),
          kick: (channelId, userId, currentRunId) =>
            this.#slack.kick?.(channelId, userId, currentRunId, deadlineAt) ??
            Promise.reject(
              new Error("Slack provenance removal capability is unavailable"),
            ),
          listChannelMembers: (channelId, currentRunId) =>
            this.#slack.listChannelMembers(channelId, currentRunId, deadlineAt),
        },
      });
      return { error: null, writes };
    } catch (error) {
      return { error: toError(error), writes: 0 };
    }
  }

  async #applyDirectChannelAdditions(
    additions: readonly ChannelMembershipChange[],
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<{ error: Error | null; writes: number }> {
    const limit = this.#config.maxAutomaticChannelInvites;
    if (additions.length === 0 || limit === 0)
      return { error: null, writes: 0 };
    if (additions.length > limit) {
      return {
        error: new Error(
          "Slack channel invitation selection exceeded its limit",
        ),
        writes: 0,
      };
    }
    if (!this.#slack.invite) {
      return {
        error: new Error("Slack channel invitation capability is unavailable"),
        writes: 0,
      };
    }
    const invite = this.#slack.invite.bind(this.#slack);
    let writes = 0;
    for (const expected of additions) {
      // eslint-disable-next-line no-await-in-loop -- each invitation has a fresh authority check and provider readback.
      const result = await this.#applyDirectChannelAddition(
        expected,
        runId,
        deadlineAt,
        assertLeaseActive,
        invite,
      );
      writes += result.writes;
      if (result.error) return { error: result.error, writes };
    }
    return { error: null, writes };
  }

  async #applyDirectChannelAddition(
    expected: ChannelMembershipChange,
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
    invite: NonNullable<IOrgChannelSlackClient["invite"]>,
  ): Promise<{ error: Error | null; writes: number }> {
    let writes = 0;
    try {
      ensureWriteBudget(deadlineAt);
      const fresh = await this.#buildPlan(runId, deadlineAt);
      if (
        fresh.plan.errors.length > 0 ||
        !fresh.plan.additions.some((current) =>
          sameChannelMembership(current, expected),
        )
      ) {
        throw new Error(
          `Google or Slack authority changed before #${expected.channelName} invitation`,
        );
      }
      const channel = await this.#slack.getChannelIdentity(
        expected.channelId,
        runId,
        deadlineAt,
      );
      if (!sameChannelIdentity(channel, expected)) {
        throw new Error(
          `Slack channel ${expected.channelId} changed before invitation`,
        );
      }
      const before = await this.#slack.listChannelMembers(
        expected.channelId,
        runId,
        deadlineAt,
      );
      if (before.includes(expected.slackUserId))
        return { error: null, writes: 0 };
      await assertLeaseActive([expected.slackUserId]);
      logChannelInvitation("started", expected, runId);
      writes = 1;
      try {
        await invite(
          expected.channelId,
          expected.slackUserId,
          runId,
          deadlineAt,
        );
      } catch (error) {
        if (!(error instanceof SlackWriteOutcomeUnknownError)) throw error;
      }
      const after = await this.#slack.listChannelMembers(
        expected.channelId,
        runId,
        deadlineAt,
      );
      if (!after.includes(expected.slackUserId)) {
        throw new Error(
          `Slack channel invitation readback failed for ${expected.channelId}`,
        );
      }
      logChannelInvitation("verified", expected, runId);
      return { error: null, writes };
    } catch (error) {
      if (writes > 0) logChannelInvitation("failed", expected, runId);
      return { error: toError(error), writes };
    }
  }

  async #assertNoRenewedProvenanceSource(
    candidate: ChannelMembershipRemovalPlan,
    sources: readonly ChannelMembershipProvenanceSource[],
    runId: string,
    deadlineAt: number,
  ): Promise<void> {
    const getUserGroupById = this.#slack.getUserGroupById?.bind(this.#slack);
    if (!getUserGroupById)
      throw new Error("Slack source membership readback is unavailable");
    const fresh = await this.#buildPlan(runId, deadlineAt);
    if (fresh.plan.errors.length > 0) {
      throw new Error(
        "Google or Slack authority is invalid before provenance removal",
      );
    }
    if (
      this.#config.contractorOnlyMemberRemovals &&
      fresh.plan.lifecycle.allTeamProjection?.excludedFromSourceMembers.filter(
        ({ slackUserId }) => slackUserId === candidate.slackUserId,
      ).length !== 1
    ) {
      throw new Error(
        "Google contractor authority changed before channel removal",
      );
    }
    for (const source of sources) {
      const matching = fresh.plan.userGroups.filter(
        (group) =>
          group.slackUserGroupId === source.slackUserGroupId &&
          group.automationOwnership.kind !== "legacy_unmanaged" &&
          sameStrings(
            group.automationOwnership.sourceGoogleGroupIds,
            source.sourceGoogleGroupIds,
          ),
      );
      if (
        matching.length !== 1 ||
        matching[0]?.desiredUserIds.includes(candidate.slackUserId)
      ) {
        throw new Error(
          "Google source authority renewed or became ambiguous before channel removal",
        );
      }
      // eslint-disable-next-line no-await-in-loop -- every recorded Slack source is independently re-read.
      const liveSource = await getUserGroupById(
        source.slackUserGroupId,
        runId,
        deadlineAt,
      );
      if (!liveSource || liveSource.userIds.includes(candidate.slackUserId)) {
        throw new Error(
          "Slack user-group source membership renewed before channel removal",
        );
      }
    }
  }

  async #applyWithOverlapGuard(
    plan: OrgChannelPlan,
    selectedChannelRename: ChannelRenameChange | null,
    selectedChannelAdditions: readonly ChannelMembershipChange[],
    selectedUserGroups: readonly SlackUserGroupReconciliation[],
    selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
    runId: string,
    deadlineAt: number,
    membershipGuard:
      | ((slackUserIds: readonly string[]) => Promise<void>)
      | undefined,
    reviewedGuard?: {
      beforeWrite(): Promise<void>;
      finalSource: SlackMembershipFinalSourceAuthority;
    },
  ): Promise<{ error: Error | null; writes: number }> {
    const leaseRepository = this.#leaseRepository;
    const execution = await withResourceLease(
      leaseRepository,
      SLACK_USER_GROUPS_RESOURCE_LEASE_KEY,
      Math.max(1, deadlineAt - Date.now() + LEASE_POST_DEADLINE_FENCE_MS),
      (lease) =>
        this.#applyChanges(
          plan,
          selectedChannelRename,
          selectedChannelAdditions,
          selectedUserGroups,
          selectedProvenanceChannelRemovals,
          runId,
          deadlineAt,
          Object.assign(
            async (slackUserIds?: readonly string[]) => {
              await leaseRepository.assertActive(
                lease,
                LEASE_POST_DEADLINE_FENCE_MS,
              );
              if (slackUserIds !== undefined)
                await membershipGuard?.(slackUserIds);
              await leaseRepository.assertActive(
                lease,
                LEASE_POST_DEADLINE_FENCE_MS,
              );
              if (slackUserIds !== undefined)
                await reviewedGuard?.beforeWrite();
            },
            {
              membershipBudgetRequired: membershipGuard !== undefined,
              reviewedFinalSource: reviewedGuard?.finalSource,
            },
          ),
        ),
    );
    if (execution.kind === "busy") {
      return {
        error: new Error("Another org channel mutation is already in flight"),
        writes: 0,
      };
    }
    return execution.result;
  }

  async #applySelectedRename(
    rename: ChannelRenameChange,
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<{ error: Error | null; writes: number }> {
    const attempt = { started: false };
    try {
      await this.#applyChannelRename(
        rename,
        attempt,
        runId,
        deadlineAt,
        assertLeaseActive,
      );
      return { error: null, writes: attempt.started ? 1 : 0 };
    } catch (error) {
      logMutationCounter("channel_rename", "failed", runId);
      logEvent("org_channel_sync.channel_rename", {
        "channel_id": rename.channelId,
        "current_name": rename.currentName,
        error: toError(error).message,
        "expected_name": rename.expectedName,
        phase: "failed",
        "run_id": runId,
      });
      return { error: toError(error), writes: attempt.started ? 1 : 0 };
    }
  }

  async #applySelectedUserGroups(
    selectedGroups: readonly SlackUserGroupReconciliation[],
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<{ error: Error | null; writes: number }> {
    let writes = 0;
    try {
      for (const group of selectedGroups) {
        const attempt = { started: false };
        try {
          // eslint-disable-next-line no-await-in-loop -- Each user-group mutation records its outcome before the next write consumes the configured limit.
          await this.#applyUserGroup(
            group,
            attempt,
            runId,
            deadlineAt,
            assertLeaseActive,
          );
        } catch (error) {
          logMutationCounter("user_group_write", "failed", runId);
          logEvent("org_channel_sync.user_group_write_failed", {
            error: toError(error).message,
            handle: group.handle,
            "run_id": runId,
          });
          if (attempt.started) writes++;
          throw error;
        }
        if (attempt.started) writes++;
      }
      return { error: null, writes };
    } catch (error) {
      return { error: toError(error), writes };
    }
  }

  async #applyUserGroup(
    expected: SlackUserGroupReconciliation,
    attempt: WriteAttempt,
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<void> {
    ensureWriteBudget(deadlineAt);
    await this.#assertFreshUserGroupPlan(expected, runId, deadlineAt);
    const removalOnly =
      contractorRemovalCandidateOnly(expected) ||
      googleGroupRemovalCandidateOnly(expected) ||
      (expected.memberRemovalAuthority === "explicit_google_lifecycle" &&
        reviewedFinalSource(assertLeaseActive) !== undefined);
    const additionOnly = membershipAdditionCandidateOnly(expected);
    const bootstrap =
      expected.automationOwnership.kind === "automation_bootstrap";
    if (
      userGroupWriteCapabilityUnavailable(
        this.#slack,
        removalOnly,
        additionOnly,
        bootstrap,
      )
    ) {
      throw new Error("Slack user-group write capability is unavailable");
    }
    const { created, userGroupId } = await this.#resolveUserGroupId(
      expected,
      expected.slackUserGroupId,
      attempt,
      runId,
      deadlineAt,
      assertLeaseActive,
    );
    if (bootstrap) {
      await this.#verifyBootstrapUserGroup(
        expected,
        userGroupId,
        created,
        runId,
        deadlineAt,
      );
      return;
    }
    const beforeUpdate = await this.#readUserGroupBeforeUpdate(
      expected,
      userGroupId,
      created,
      runId,
      deadlineAt,
    );
    if (
      expected.memberRemovals.length > 0 &&
      !sameStrings(beforeUpdate?.channelIds ?? [], expected.desiredChannelIds)
    ) {
      throw new Error(
        `Slack user group @${expected.handle} gained an unreviewed channel association before removal`,
      );
    }
    const { channelIds: writeChannelIds, userIds: writeUserIds } =
      buildUserGroupWriteState(expected, beforeUpdate);
    if (removalOnly) {
      await this.#applyRemovalOnlyUserGroup(
        expected,
        userGroupId,
        writeUserIds,
        attempt,
        runId,
        deadlineAt,
        assertLeaseActive,
      );
      return;
    }
    if (additionOnly) {
      await this.#applyAdditionOnlyUserGroup(
        expected,
        userGroupId,
        attempt,
        runId,
        deadlineAt,
        assertLeaseActive,
      );
      return;
    }
    await this.#applyUserGroupUpdate(
      expected,
      userGroupId,
      writeChannelIds,
      writeUserIds,
      attempt,
      runId,
      deadlineAt,
      assertLeaseActive,
    );
  }

  async #assertFreshUserGroupPlan(
    expected: SlackUserGroupReconciliation,
    runId: string,
    deadlineAt: number,
  ): Promise<void> {
    const fresh = await this.#buildPlan(runId, deadlineAt);
    const freshGroupCandidate =
      expected.memberAdditions.length > 0 ||
      expected.channelRemovals.length > 0 ||
      expected.memberRemovalAuthority !== "explicit_google_lifecycle"
        ? selectUserGroupsForWrite(fresh.plan, this.#config, true).find(
            (group) => group.handle === expected.handle,
          )
        : fresh.plan.userGroups.find(
            (group) => group.handle === expected.handle,
          );
    const freshContractorIds = new Set(
      fresh.plan.lifecycle.allTeamProjection?.excludedFromSourceMembers.map(
        ({ slackUserId }) => slackUserId,
      ),
    );
    let freshEligibleGroup = freshGroupCandidate;
    if (
      freshGroupCandidate &&
      expected.memberRemovalAuthority === "contractor_group_authoritative"
    ) {
      freshEligibleGroup =
        contractorOnlyMemberRemovalCandidate(
          freshGroupCandidate,
          freshContractorIds,
        ) ?? undefined;
    }
    const freshGroup = freshEligibleGroup
      ? limitAdditionBatch(
          limitRemovalBatch(
            freshEligibleGroup,
            removalLimitForGroup(freshEligibleGroup, this.#config),
          ),
        )
      : undefined;
    if (
      fresh.plan.errors.length > 0 ||
      !freshGroup ||
      !sameUserGroupPlan(freshGroup, expected)
    ) {
      throw new Error(
        `Google or Slack authority changed before @${expected.handle} write`,
      );
    }
  }

  async #verifyBootstrapUserGroup(
    expected: SlackUserGroupReconciliation,
    userGroupId: string,
    created: boolean,
    correlationId: string,
    deadlineAt: number,
  ): Promise<void> {
    if (!created)
      throw new Error(
        `Slack user group @${expected.handle} bootstrap was not created`,
      );
    const getUserGroup = this.#slack.getUserGroup?.bind(this.#slack);
    if (!getUserGroup)
      throw new Error("Slack user-group write capability is unavailable");
    const getUserGroupById = this.#slack.getUserGroupById?.bind(this.#slack);
    const actual = getUserGroupById
      ? await getUserGroupById(userGroupId, correlationId, deadlineAt)
      : await getUserGroup(expected.handle, correlationId, deadlineAt);
    if (
      actual?.id !== userGroupId ||
      !matchesCreatedUserGroup(actual, expected)
    ) {
      throw new Error(
        `Slack user group @${expected.handle} bootstrap readback failed`,
      );
    }
    logUserGroupWrite("verified", expected, correlationId);
  }

  async #applyRemovalOnlyUserGroup(
    expected: SlackUserGroupReconciliation,
    userGroupId: string,
    writeUserIds: readonly string[],
    attempt: WriteAttempt,
    correlationId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<void> {
    const removeUserGroupMembers = this.#slack.removeUserGroupMembers?.bind(
      this.#slack,
    );
    const getUserGroupById = this.#slack.getUserGroupById?.bind(this.#slack);
    if (!removeUserGroupMembers || !getUserGroupById) {
      throw new Error(
        "Slack removal-only user-group capability is unavailable",
      );
    }
    await assertLeaseActive();
    const applied = await removeUserGroupMembers(
      userGroupId,
      expected.handle,
      expected.desiredName,
      expected.desiredChannelIds,
      writeUserIds,
      plannedCurrentUserIds(expected),
      expected.memberRemovals.map(({ slackUserId }) => slackUserId),
      correlationId,
      deadlineAt,
      () => {
        attempt.started = true;
        logUserGroupWrite("started", expected, correlationId);
      },
      ...membershipCallbacks(assertLeaseActive),
      ...reviewedFinalSourceCallbacks(assertLeaseActive),
    );
    if (applied.wrote !== attempt.started) {
      throw new Error(
        "Slack removal-only write accounting did not match the mutation attempt",
      );
    }
    const actual = await getUserGroupById(
      userGroupId,
      correlationId,
      deadlineAt,
    );
    verifyUserGroupReadback(
      expected,
      actual,
      userGroupId,
      expected.desiredChannelIds,
      applied.userIds,
    );
    if (applied.wrote) logUserGroupWrite("verified", expected, correlationId);
    if (applied.wrote && this.#provenanceRepository) {
      await this.#provenanceRepository.releaseSource({
        runId: correlationId,
        slackUserGroupId: userGroupId,
        slackUserIds: expected.memberRemovals.map(
          ({ slackUserId }) => slackUserId,
        ),
      });
    }
  }

  async #applyAdditionOnlyUserGroup(
    expected: SlackUserGroupReconciliation,
    userGroupId: string,
    attempt: WriteAttempt,
    correlationId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<void> {
    const addUserGroupMembers = this.#slack.addUserGroupMembers?.bind(
      this.#slack,
    );
    const getUserGroupById = this.#slack.getUserGroupById?.bind(this.#slack);
    if (!addUserGroupMembers || !getUserGroupById) {
      throw new Error(
        "Slack addition-only user-group capability is unavailable",
      );
    }
    const reviewedAdditionUserIds = expected.memberAdditions.map(
      ({ slackUserId }) => slackUserId,
    );
    const provenanceBefore = await this.#captureProvenanceMembership(
      expected,
      reviewedAdditionUserIds,
      expected.requiredChannelIds,
      correlationId,
      deadlineAt,
    );
    await assertLeaseActive();
    const applied = await addUserGroupMembers(
      userGroupId,
      expected.handle,
      expected.desiredName,
      expected.requiredChannelIds,
      plannedCurrentUserIds(expected),
      reviewedAdditionUserIds,
      correlationId,
      deadlineAt,
      () => {
        attempt.started = true;
        logUserGroupWrite("started", expected, correlationId);
      },
      ...membershipCallbacks(assertLeaseActive),
    );
    if (applied.wrote !== attempt.started) {
      throw new Error(
        "Slack addition-only write accounting did not match the mutation attempt",
      );
    }
    const actual = await getUserGroupById(
      userGroupId,
      correlationId,
      deadlineAt,
    );
    if (
      actual?.id !== userGroupId ||
      actual.isDisabled ||
      actual.handle !== expected.handle ||
      actual.name !== expected.desiredName ||
      !sameStrings(actual.channelIds, expected.requiredChannelIds) ||
      applied.userIds.some((userId) => !actual.userIds.includes(userId))
    ) {
      throw new Error(
        `Slack user group @${expected.handle} addition-only readback failed`,
      );
    }
    if (applied.wrote) {
      await this.#recordProvenanceMembership(
        expected,
        userGroupId,
        provenanceBefore,
        correlationId,
        deadlineAt,
      );
      logUserGroupWrite("verified", expected, correlationId);
    }
  }

  async #applyUserGroupUpdate(
    expected: SlackUserGroupReconciliation,
    userGroupId: string,
    writeChannelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    writeUserIds: readonly string[],
    attempt: WriteAttempt,
    correlationId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<void> {
    const provenanceBefore = await this.#captureProvenanceMembership(
      expected,
      expected.memberAdditions.map(({ slackUserId }) => slackUserId),
      writeChannelIds,
      correlationId,
      deadlineAt,
    );
    await assertLeaseActive();
    const updateUserGroup = this.#slack.updateUserGroup?.bind(this.#slack);
    if (!updateUserGroup)
      throw new Error("Slack user-group update capability is unavailable");
    const onMutationStart = () => {
      if (attempt.started) return;
      attempt.started = true;
      logUserGroupWrite("started", expected, correlationId);
    };
    const membershipGuard = membershipCallbacks(assertLeaseActive)[0];
    if (membershipGuard === undefined) onMutationStart();
    const callbacks: [
      beforeMembershipMutation?: (ids: readonly string[]) => Promise<void>,
      onMutationStart?: () => void,
    ] = membershipGuard === undefined ? [] : [membershipGuard, onMutationStart];
    await updateUserGroup(
      userGroupId,
      expected.desiredName,
      expected.handle,
      writeChannelIds,
      writeUserIds,
      effectiveMembershipWriteMode(expected),
      correlationId,
      deadlineAt,
      plannedCurrentUserIds(expected),
      expected.memberRemovals.map(({ slackUserId }) => slackUserId),
      callbacks[0],
      callbacks[1],
      plannedCurrentChannelIds(expected),
      expected.channelRemovals.map(({ id }) => id),
    );
    const getUserGroup = this.#slack.getUserGroup?.bind(this.#slack);
    if (!getUserGroup)
      throw new Error("Slack user-group reads are unavailable");
    const actual = await getUserGroup(
      expected.handle,
      correlationId,
      deadlineAt,
    );
    verifyUserGroupReadback(
      expected,
      actual,
      userGroupId,
      writeChannelIds,
      writeUserIds,
    );
    await this.#recordProvenanceMembership(
      expected,
      userGroupId,
      provenanceBefore,
      correlationId,
      deadlineAt,
    );
    if (expected.memberRemovals.length > 0 && this.#provenanceRepository) {
      await this.#provenanceRepository.releaseSource({
        runId: correlationId,
        slackUserGroupId: userGroupId,
        slackUserIds: expected.memberRemovals.map(
          ({ slackUserId }) => slackUserId,
        ),
      });
    }
    logUserGroupWrite("verified", expected, correlationId);
  }

  async #captureProvenanceMembership(
    expected: SlackUserGroupReconciliation,
    slackUserIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    writeChannelIds: readonly string[],
    correlationId: string,
    deadlineAt: number,
  ): Promise<Map<string, Set<string>>> {
    const snapshots = new Map<string, Set<string>>();
    if (
      !this.#provenanceRepository ||
      slackUserIds.length === 0 ||
      expected.automationOwnership.kind === "legacy_unmanaged"
    )
      return snapshots;
    const captureChannelIds = selectProvenanceCaptureChannelIds(
      writeChannelIds,
      expected.automationOwnership.allowedChannelIds,
    );
    for (const channelId of captureChannelIds) {
      // eslint-disable-next-line no-await-in-loop -- each pre-write snapshot is provenance evidence.
      const members = await this.#slack.listChannelMembers(
        channelId,
        correlationId,
        deadlineAt,
      );
      snapshots.set(channelId, new Set(members));
    }
    return snapshots;
  }

  async #recordProvenanceMembership(
    expected: SlackUserGroupReconciliation,
    slackUserGroupId: string,
    before: ReadonlyMap<string, ReadonlySet<string>>,
    correlationId: string,
    deadlineAt: number,
  ): Promise<void> {
    if (
      !this.#provenanceRepository ||
      before.size === 0 ||
      expected.automationOwnership.kind === "legacy_unmanaged"
    )
      return;
    const observations: ChannelMembershipObservation[] = [];
    for (const [channelId, beforeMembers] of before) {
      const afterMembers = new Set(
        // eslint-disable-next-line no-await-in-loop -- exact post-write snapshots close provenance evidence.
        await this.#slack.listChannelMembers(
          channelId,
          correlationId,
          deadlineAt,
        ),
      );
      for (const { slackUserId } of expected.memberAdditions) {
        observations.push({
          afterMember: afterMembers.has(slackUserId),
          beforeMember: beforeMembers.has(slackUserId),
          channelId,
          slackUserId,
        });
      }
    }
    await this.#provenanceRepository.recordAdditionObservations({
      observations,
      runId: correlationId,
      slackUserGroupId,
      sourceGoogleGroupIds: expected.automationOwnership.sourceGoogleGroupIds,
    });
  }

  async #applyChannelRename(
    expected: ChannelRenameChange,
    attempt: WriteAttempt,
    runId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<void> {
    ensureWriteBudget(deadlineAt);
    const fresh = await this.#buildPlan(runId, deadlineAt);
    const freshRename = fresh.plan.channelRenames.find(
      (rename) => rename.channelId === expected.channelId,
    );
    const freshSelectedUserGroups = selectUserGroupsForWrite(
      fresh.plan,
      this.#config,
      false,
    );
    if (
      fresh.plan.errors.length > 0 ||
      freshSelectedUserGroups.length > 0 ||
      !freshRename ||
      !sameRename(freshRename, expected)
    ) {
      throw new Error(
        `Google or Slack authority changed before #${expected.currentName} rename`,
      );
    }
    if (!this.#slack.renameChannel)
      throw new Error("Slack channel rename capability is unavailable");
    const before = await this.#slack.getChannelIdentity(
      expected.channelId,
      runId,
      deadlineAt,
    );
    if (
      before.id !== expected.channelId ||
      before.name !== expected.currentName ||
      before.isArchived ||
      before.isPrivate !== expected.isPrivate
    ) {
      throw new Error(
        `Slack channel ${expected.channelId} changed before rename`,
      );
    }
    await assertLeaseActive();
    attempt.started = true;
    logMutationCounter("channel_rename", "attempted", runId);
    logEvent("org_channel_sync.channel_rename", {
      "channel_id": expected.channelId,
      "current_name": expected.currentName,
      "expected_name": expected.expectedName,
      phase: "started",
      "run_id": runId,
    });
    await this.#slack.renameChannel(
      expected.channelId,
      expected.expectedName,
      runId,
      deadlineAt,
    );
    const after = await this.#slack.getChannelIdentity(
      expected.channelId,
      runId,
      deadlineAt,
    );
    if (
      after.id !== expected.channelId ||
      after.name !== expected.expectedName ||
      after.isPrivate !== expected.isPrivate ||
      after.isArchived
    ) {
      throw new Error(
        `Slack channel rename read-back failed for ${expected.channelId}`,
      );
    }
    logMutationCounter("channel_rename", "verified", runId);
    logEvent("org_channel_sync.channel_rename", {
      "channel_id": expected.channelId,
      "current_name": expected.currentName,
      "expected_name": expected.expectedName,
      phase: "verified",
      "run_id": runId,
    });
  }

  async #readUserGroupBeforeUpdate(
    expected: SlackUserGroupReconciliation,
    userGroupId: string,
    created: boolean,
    correlationId: string,
    deadlineAt: number,
  ) {
    if (!this.#slack.getUserGroup) {
      throw new Error("Slack user-group reads are unavailable");
    }
    const current = this.#slack.getUserGroupById
      ? await this.#slack.getUserGroupById(
          userGroupId,
          correlationId,
          deadlineAt,
        )
      : await this.#slack.getUserGroup(
          expected.currentHandle ?? expected.handle,
          correlationId,
          deadlineAt,
        );
    if (!current && !created) {
      throw new Error(
        `Slack user group @${expected.handle} disappeared before update`,
      );
    }
    if (current && current.id !== userGroupId) {
      throw new Error(
        `Slack user group @${expected.handle} changed identity before update`,
      );
    }
    return current;
  }

  async #resolveUserGroupId(
    expected: SlackUserGroupReconciliation,
    existingId: null | string,
    attempt: WriteAttempt,
    correlationId: string,
    deadlineAt: number,
    assertLeaseActive: (slackUserIds?: readonly string[]) => Promise<void>,
  ): Promise<{ created: boolean; userGroupId: string }> {
    if (existingId) return { created: false, userGroupId: existingId };
    if (!this.#slack.createUserGroup || !this.#slack.getUserGroup) {
      throw new Error("Slack user-group creation is unavailable");
    }
    try {
      await assertLeaseActive();
      attempt.started = true;
      logUserGroupWrite("started", expected, correlationId);
      const userGroupId = await this.#slack.createUserGroup(
        expected.desiredName,
        expected.handle,
        expected.desiredChannelIds,
        correlationId,
        deadlineAt,
      );
      return { created: true, userGroupId };
    } catch (error) {
      if (!(error instanceof SlackWriteOutcomeUnknownError)) throw error;
      throw new Error(
        `Slack user group @${expected.handle} create outcome is ambiguous and requires review`,
        { cause: error },
      );
    }
  }
}

export function channelRenameSelectionAllowed(
  selectedUserGroupHandles: readonly string[],
  selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
): boolean {
  return (
    selectedUserGroupHandles.length === 0 &&
    selectedProvenanceChannelRemovals.length === 0
  );
}

function matchesCreatedUserGroup(
  actual: SlackUserGroupSnapshot,
  expected: SlackUserGroupReconciliation,
): boolean {
  return (
    actual.handle === expected.handle &&
    actual.name === expected.desiredName &&
    actual.userIds.length === 0 &&
    sameStrings(actual.channelIds, expected.desiredChannelIds)
  );
}

function membershipCallbacks(
  assertLeaseActive: (ids?: readonly string[]) => Promise<void>,
): [(ids: readonly string[]) => Promise<void>] | [] {
  return "membershipBudgetRequired" in assertLeaseActive &&
    assertLeaseActive.membershipBudgetRequired === true
    ? [(ids) => assertLeaseActive(ids)]
    : [];
}

type ReviewedMembershipAuthority = ((
  ids?: readonly string[],
) => Promise<void>) & {
  reviewedFinalSource?: SlackMembershipFinalSourceAuthority | undefined;
};

function reviewedFinalSource(
  callback: ReviewedMembershipAuthority,
): SlackMembershipFinalSourceAuthority | undefined {
  return callback.reviewedFinalSource;
}

function reviewedFinalSourceCallbacks(
  callback: (ids?: readonly string[]) => Promise<void>,
): [] | [SlackMembershipFinalSourceAuthority] {
  const value = reviewedFinalSource(callback);
  return value === undefined ? [] : [value];
}

interface SnapshotPlan {
  channels: SlackChannelIdentity[];
  directoryUsers: readonly GoogleDirectoryUser[];
  observedChannels: SlackChannelSyncSnapshot["channels"];
  observedUserGroups: SlackChannelSyncSnapshot["userGroups"];
  plan: OrgChannelPlan;
  scopes: string[];
  slackMembers: readonly SlackMember[];
}

interface WriteAttempt {
  started: boolean;
}

function appendDeferredChangeWarnings(
  plan: OrgChannelPlan,
  config: OrgChannelSyncConfig,
  scopes: readonly string[],
): void {
  const userGroupChanges = plan.userGroups.filter(
    (group) => group.status !== "in_sync",
  ).length;
  const userGroupWriteLimit = config.maxAutomaticUserGroupChanges ?? 0;
  if (userGroupChanges > userGroupWriteLimit) {
    plan.warnings.push(
      `${String(userGroupChanges - userGroupWriteLimit)} Slack user-group changes deferred by the per-run safety ceiling`,
    );
  }
  if (plan.channelRenames.length > 0 && userGroupChanges > 0) {
    plan.warnings.push(
      `${String(plan.channelRenames.length)} Slack channel renames deferred until user-group changes converge`,
    );
    return;
  }
  const renameLimit = config.maxAutomaticChannelRenames ?? 0;
  if (plan.channelRenames.length > renameLimit) {
    plan.warnings.push(
      `${String(plan.channelRenames.length - renameLimit)} Slack channel renames deferred by the per-run safety ceiling`,
    );
  }
  const unsupportedRenames = plan.channelRenames.filter(
    (rename) => !canRenameChannel(rename, scopes),
  ).length;
  if (unsupportedRenames > 0) {
    plan.warnings.push(
      `${String(unsupportedRenames)} Slack channel renames deferred because the dedicated token lacks the matching write scope`,
    );
  }
}

function validateSnapshot(
  plan: OrgChannelPlan,
  input: {
    activeGoogleUsers: number;
    expectedSlackTeamId: string;
    minimumActiveGoogleUsers: number;
    requireUserGroups: boolean;
    scopes: readonly string[];
    teamId: string;
  },
): void {
  if (input.teamId !== input.expectedSlackTeamId) {
    plan.errors.push(
      `Slack workspace ${input.teamId} does not match configured workspace`,
    );
  }
  if (input.activeGoogleUsers < input.minimumActiveGoogleUsers) {
    plan.errors.push(
      `Active Google population ${String(input.activeGoogleUsers)} is below safety floor ${String(input.minimumActiveGoogleUsers)}`,
    );
  }
  const scopeSet = new Set(input.scopes);
  const missingScopes: string[] = REQUIRED_SLACK_READ_SCOPES.filter(
    (scope) => !scopeSet.has(scope),
  );
  if (input.requireUserGroups && !scopeSet.has("usergroups:read")) {
    missingScopes.push("usergroups:read");
  }
  if (missingScopes.length > 0) {
    plan.errors.push(
      `Slack token is missing read scopes: ${missingScopes.join(", ")}`,
    );
  }
  plan.errors = [...new Set(plan.errors)].toSorted((left, right) =>
    left.localeCompare(right),
  );
}

function liveSafetyError(
  plan: OrgChannelPlan,
  selectedChannelAdditions: readonly ChannelMembershipChange[],
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
  selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
  selectedChannelRename: ChannelRenameChange | null,
  options: OrgChannelSyncRunOptions,
  config: OrgChannelSyncConfig,
  planHash: string,
): null | string {
  const renameError = channelRenameSafetyError(plan, options, config, planHash);
  if (renameError) return renameError;
  const directRemovalError = directContractorRemovalSafetyError(
    plan,
    selectedChannelAdditions,
    selectedUserGroups,
    selectedProvenanceChannelRemovals,
    selectedChannelRename,
  );
  if (directRemovalError) return directRemovalError;
  return userGroupAndMembershipSafetyError(
    plan,
    selectedChannelAdditions,
    selectedUserGroups,
    selectedProvenanceChannelRemovals,
    options,
    config,
    planHash,
  );
}

function directContractorRemovalSafetyError(
  plan: OrgChannelPlan,
  selectedChannelAdditions: readonly ChannelMembershipChange[],
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
  selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
  selectedChannelRename: ChannelRenameChange | null,
): null | string {
  if (
    selectedUserGroups.length > 0 ||
    selectedChannelAdditions.length > 0 ||
    selectedProvenanceChannelRemovals.length > 0 ||
    selectedChannelRename !== null ||
    plan.removals.length === 0
  ) {
    return null;
  }
  return "Direct Slack channel membership writes are disabled; use Slack user groups";
}

function channelRenameSafetyError(
  plan: OrgChannelPlan,
  options: OrgChannelSyncRunOptions,
  config: OrgChannelSyncConfig,
  planHash: string,
): null | string {
  if (plan.userGroups.some((group) => group.status !== "in_sync")) return null;
  const maxChannelRenames = config.maxAutomaticChannelRenames ?? 0;
  if (plan.channelRenames.length > 0 && maxChannelRenames === 0) {
    return "Safety stop: Slack channel renames are disabled by the zero-change limit";
  }
  if (plan.channelRenames.length > 0 && options.expectedPlanHash !== planHash) {
    return `Safety stop: this exact channel rename plan requires approval hash ${planHash}`;
  }
  return null;
}

function userGroupAndMembershipSafetyError(
  plan: OrgChannelPlan,
  selectedChannelAdditions: readonly ChannelMembershipChange[],
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
  selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
  options: OrgChannelSyncRunOptions,
  config: OrgChannelSyncConfig,
  planHash: string,
): null | string {
  if (
    options.expectedPlanHash !== undefined &&
    options.expectedPlanHash !== planHash
  ) {
    return `Safety stop: supplied user-group approval hash does not match plan ${planHash}`;
  }
  const maxUserGroupChanges = config.maxAutomaticUserGroupChanges ?? 0;
  const userGroupChanges = plan.userGroups.filter(
    (group) => group.status !== "in_sync",
  );
  const memberAdditions = selectedUserGroups.reduce(
    (total, group) => total + group.memberAdditions.length,
    0,
  );
  const memberRemovals = selectedUserGroups.reduce(
    (total, group) => total + group.memberRemovals.length,
    0,
  );
  const channelAccessAdditions = selectedUserGroups.reduce(
    (total, group) => total + group.effectiveAccessAdditions.length,
    0,
  );
  const channelAssociationRemovals = selectedUserGroups.reduce(
    (total, group) => total + group.channelRemovals.length,
    0,
  );
  const totalAdditions =
    selectedChannelAdditions.length + memberAdditions + channelAccessAdditions;
  const totalUserGroupRemovals = memberRemovals + channelAssociationRemovals;
  const totalRemovals =
    totalUserGroupRemovals + selectedProvenanceChannelRemovals.length;
  const pendingUserGroupRemovals = userGroupChanges.reduce(
    (total, group) => total + userGroupRemovalCount(group),
    0,
  );
  const removalAuthority = selectedRemovalAuthority(selectedUserGroups);
  const contractorRemovalOnly =
    removalAuthority === "contractor_group_authoritative";
  const contractorRemovalLimit = config.maxAutomaticContractorRemovals ?? 0;
  const approvedAutomaticContractorRemoval =
    selectedUserGroups.length > 0 &&
    contractorRemovalOnly &&
    totalRemovals <= contractorRemovalLimit &&
    config.requireRemovalPlanHash !== true;
  const provenanceError = userGroupRemovalProvenanceError(selectedUserGroups);
  if (provenanceError) return provenanceError;
  const gateError = userGroupWriteGateError({
    approvedAutomaticContractorRemoval,
    hasSelectedNonUserGroupWork:
      selectedChannelAdditions.length > 0 ||
      selectedProvenanceChannelRemovals.length > 0,
    maxUserGroupChanges,
    options,
    pendingUserGroupRemovals,
    planHash,
    selectedUserGroups,
    userGroupChanges: userGroupChanges.length,
  });
  if (gateError) return gateError;
  if (totalAdditions > config.maxAutomaticAdditions) {
    return `Safety stop: ${String(totalAdditions)} additions exceed the limit ${String(config.maxAutomaticAdditions)}`;
  }
  const combinedRemovalError = combinedRemovalSafetyError(
    totalUserGroupRemovals,
    selectedProvenanceChannelRemovals.length,
    options.allowRemovals,
  );
  if (combinedRemovalError) return combinedRemovalError;
  if (options.allowRemovals && totalAdditions > 0 && totalRemovals > 0) {
    return "Safety stop: additions must converge before a separate destructive removal run";
  }
  return removalSafetyError({
    approvedAutomaticContractorRemoval,
    allowRemovals: options.allowRemovals,
    expectedPlanHash: options.expectedPlanHash,
    planHash,
    removalLimit:
      selectedProvenanceChannelRemovals.length > 0
        ? (config.maxAutomaticChannelMembershipRemovals ?? 0)
        : selectedRemovalLimit(
            removalAuthority,
            config,
            contractorRemovalLimit,
          ),
    totalRemovals,
  });
}

function combinedRemovalSafetyError(
  userGroupRemovals: number,
  provenanceChannelRemovals: number,
  allowRemovals: boolean,
): null | string {
  const total = userGroupRemovals + provenanceChannelRemovals;
  if (total > 0 && !allowRemovals) {
    return `Safety stop: ${String(total)} Slack removals require the removal gate`;
  }
  if (userGroupRemovals > 0 && provenanceChannelRemovals > 0) {
    return "Safety stop: user-group and provenance channel removals require separate runs";
  }
  return null;
}

function userGroupRemovalProvenanceError(
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
): null | string {
  for (const group of selectedUserGroups) {
    if (userGroupRemovalCount(group) === 0) continue;
    const error = userGroupRemovalProvenanceErrorForGroup(group);
    if (error) return error;
  }
  return null;
}

function userGroupRemovalProvenanceErrorForGroup(
  group: SlackUserGroupReconciliation,
): null | string {
  const ownershipKind = group.automationOwnership.kind;
  if (
    ownershipKind !== "automation_created" &&
    ownershipKind !== "explicitly_adopted"
  ) {
    return `Safety stop: Slack user group @${group.handle} has no reviewed automation ownership cutover`;
  }
  if (!group.expectedSlackUserGroupId) {
    return `Safety stop: Slack user group @${group.handle} removals require a pinned immutable group ID`;
  }
  if (group.slackUserGroupId !== group.expectedSlackUserGroupId) {
    return `Safety stop: Slack user group @${group.handle} does not match its pinned immutable group ID`;
  }
  if (
    group.currentHandle !== group.handle ||
    group.currentName !== group.desiredName
  ) {
    return `Safety stop: Slack user group @${group.handle} is not already canonical`;
  }
  const channelRemovalBatch = channelAssociationRemovalCandidateOnly(group);
  if (
    !stringsAreSubset(
      group.requiredChannelIds,
      group.automationOwnership.allowedChannelIds,
    ) ||
    (!channelRemovalBatch &&
      !stringsAreSubset(
        group.desiredChannelIds,
        group.automationOwnership.allowedChannelIds,
      )) ||
    (channelRemovalBatch &&
      group.channelRemovals.some(
        ({ id }) =>
          group.automationOwnership.kind === "legacy_unmanaged" ||
          group.automationOwnership.allowedChannelIds.includes(id),
      ))
  ) {
    return `Safety stop: Slack user group @${group.handle} does not match its immutable channel allowlist`;
  }
  if (!ownershipMatchesGoogleAuthority(group)) {
    return `Safety stop: Slack user group @${group.handle} does not match its immutable Google group authority`;
  }
  return null;
}

function userGroupWriteGateError(input: {
  approvedAutomaticContractorRemoval: boolean;
  hasSelectedNonUserGroupWork: boolean;
  maxUserGroupChanges: number;
  options: OrgChannelSyncRunOptions;
  pendingUserGroupRemovals: number;
  planHash: string;
  selectedUserGroups: readonly SlackUserGroupReconciliation[];
  userGroupChanges: number;
}): null | string {
  if (
    input.userGroupChanges > 0 &&
    input.maxUserGroupChanges === 0 &&
    !input.hasSelectedNonUserGroupWork
  ) {
    return "Safety stop: Slack user-group writes are disabled by the zero-change limit";
  }
  if (
    removalGateBlocksOnlyPendingWork(
      input.selectedUserGroups,
      input.pendingUserGroupRemovals,
      input.options,
      input.hasSelectedNonUserGroupWork,
    )
  ) {
    return `Safety stop: ${String(input.pendingUserGroupRemovals)} Slack user-group removals require the removal gate`;
  }
  if (
    input.userGroupChanges > 0 &&
    (input.selectedUserGroups.length > 0 ||
      !input.hasSelectedNonUserGroupWork) &&
    !input.approvedAutomaticContractorRemoval &&
    input.options.expectedPlanHash !== input.planHash
  ) {
    return `Safety stop: this exact user-group plan requires approval hash ${input.planHash}`;
  }
  return null;
}

function removalSafetyError(input: {
  approvedAutomaticContractorRemoval: boolean;
  allowRemovals: boolean;
  expectedPlanHash?: string | undefined;
  planHash: string;
  removalLimit: number;
  totalRemovals: number;
}): null | string {
  if (input.totalRemovals === 0 || !input.allowRemovals) return null;
  if (input.totalRemovals > input.removalLimit) {
    return `Safety stop: ${String(input.totalRemovals)} removals exceed the limit ${String(input.removalLimit)}`;
  }
  if (
    !input.approvedAutomaticContractorRemoval &&
    input.expectedPlanHash !== input.planHash
  ) {
    return `Safety stop: this exact removal plan requires approval hash ${input.planHash}`;
  }
  return null;
}

function contractorRemovalCandidateOnly(
  group: SlackUserGroupReconciliation,
): boolean {
  return (
    group.memberRemovalAuthority === "contractor_group_authoritative" &&
    group.memberRemovals.length > 0 &&
    group.memberAdditions.length === 0 &&
    group.channelAdditions.length === 0 &&
    group.channelRemovals.length === 0 &&
    group.effectiveAccessAdditions.length === 0
  );
}

function googleGroupRemovalCandidateOnly(
  group: SlackUserGroupReconciliation,
): boolean {
  return (
    group.memberRemovalAuthority === "google_group_authoritative" &&
    group.memberRemovals.length > 0 &&
    group.memberAdditions.length === 0 &&
    group.channelAdditions.length === 0 &&
    group.channelRemovals.length === 0 &&
    group.effectiveAccessAdditions.length === 0
  );
}

function supportedAutomaticRemovalCandidateOnly(
  group: SlackUserGroupReconciliation,
): boolean {
  return (
    contractorRemovalCandidateOnly(group) ||
    googleGroupRemovalCandidateOnly(group) ||
    channelAssociationRemovalCandidateOnly(group)
  );
}

function channelAssociationRemovalCandidateOnly(
  group: SlackUserGroupReconciliation,
): boolean {
  return (
    group.memberAdditions.length === 0 &&
    group.memberRemovals.length === 0 &&
    group.channelAdditions.length === 0 &&
    group.channelRemovals.length === 1 &&
    group.effectiveAccessAdditions.length === 0
  );
}

function removalLimitForGroup(
  group: SlackUserGroupReconciliation,
  config: OrgChannelSyncConfig,
): number {
  if (contractorRemovalCandidateOnly(group))
    return config.maxAutomaticContractorRemovals ?? 0;
  if (googleGroupRemovalCandidateOnly(group))
    return config.maxAutomaticGoogleGroupRemovals ?? 0;
  return config.maxAutomaticRemovals;
}

function selectedRemovalAuthority(
  groups: readonly SlackUserGroupReconciliation[],
): null | SlackUserGroupReconciliation["memberRemovalAuthority"] {
  if (groups.length === 0) return null;
  const authorities = new Set(
    groups.map((group) => group.memberRemovalAuthority),
  );
  return authorities.size === 1
    ? (authorities.values().next().value ?? null)
    : null;
}

function selectedRemovalLimit(
  authority: null | SlackUserGroupReconciliation["memberRemovalAuthority"],
  config: OrgChannelSyncConfig,
  contractorRemovalLimit: number,
): number {
  if (authority === "contractor_group_authoritative")
    return contractorRemovalLimit;
  if (authority === "google_group_authoritative")
    return config.maxAutomaticGoogleGroupRemovals ?? 0;
  return config.maxAutomaticRemovals;
}

function removalGateBlocksOnlyPendingWork(
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
  pendingUserGroupRemovals: number,
  options: OrgChannelSyncRunOptions,
  hasSelectedNonUserGroupWork: boolean,
): boolean {
  return (
    selectedUserGroups.length === 0 &&
    !hasSelectedNonUserGroupWork &&
    pendingUserGroupRemovals > 0 &&
    !options.allowRemovals
  );
}

function selectUserGroupsForWrite(
  plan: OrgChannelPlan,
  config: OrgChannelSyncConfig,
  allowRemovals: boolean,
): SlackUserGroupReconciliation[] {
  const writeLimit = config.maxAutomaticUserGroupChanges ?? 0;
  const workspaceContractorIds = new Set(
    plan.lifecycle.allTeamProjection?.excludedFromSourceMembers.map(
      ({ slackUserId }) => slackUserId,
    ),
  );
  const contractorOnlyGate = config.contractorOnlyMemberRemovals === true;
  const protectedSlackUserIds = new Set(config.protectedSlackUserIds);
  return plan.userGroups
    .filter((candidate) => candidate.status !== "in_sync")
    .toSorted(compareUserGroupRolloutPriority)
    .map(
      (candidate) =>
        selectMembershipAdditionOnly(candidate, config) ?? candidate,
    )
    .map((candidate) =>
      selectSingleAuthoritativeRemoval(candidate, config, allowRemovals),
    )
    .map((candidate) =>
      deferProtectedMembershipAdditions(candidate, protectedSlackUserIds),
    )
    .filter(
      (candidate): candidate is SlackUserGroupReconciliation =>
        candidate !== null,
    )
    .map((candidate) =>
      contractorOnlyGate
        ? contractorOnlyMemberRemovalCandidate(
            candidate,
            workspaceContractorIds,
          )
        : candidate,
    )
    .filter(
      (candidate): candidate is SlackUserGroupReconciliation =>
        candidate !== null,
    )
    .filter((candidate) =>
      userGroupCandidateIsExecutable(candidate, config, allowRemovals),
    )
    .slice(0, writeLimit)
    .map((candidate) =>
      limitRemovalBatch(candidate, removalLimitForGroup(candidate, config)),
    )
    .map((candidate) => limitAdditionBatch(candidate));
}

function deferProtectedMembershipAdditions(
  group: SlackUserGroupReconciliation,
  protectedSlackUserIds: ReadonlySet<string>,
): null | SlackUserGroupReconciliation {
  if (!membershipAdditionCandidateOnly(group)) return group;
  const memberAdditions = group.memberAdditions.filter(
    ({ slackUserId }) => !protectedSlackUserIds.has(slackUserId),
  );
  if (memberAdditions.length === group.memberAdditions.length) return group;
  if (memberAdditions.length === 0) return null;
  const selectedUserIds = new Set(
    memberAdditions.map(({ slackUserId }) => slackUserId),
  );
  const deferredUserIds = new Set(
    group.memberAdditions
      .filter(({ slackUserId }) => protectedSlackUserIds.has(slackUserId))
      .map(({ slackUserId }) => slackUserId),
  );
  return {
    ...group,
    desiredUserIds: group.desiredUserIds.filter(
      (slackUserId) => !deferredUserIds.has(slackUserId),
    ),
    effectiveAccessAdditions: group.effectiveAccessAdditions.filter(
      ({ slackUserId }) => selectedUserIds.has(slackUserId),
    ),
    memberAdditions,
  };
}

function selectMembershipAdditionOnly(
  group: SlackUserGroupReconciliation,
  config: OrgChannelSyncConfig,
): null | SlackUserGroupReconciliation {
  if (
    group.memberAdditions.length === 0 ||
    group.memberAdditions.length + group.effectiveAccessAdditions.length >
      config.maxAutomaticAdditions ||
    group.channelRemovals.length > 0 ||
    group.status !== "update" ||
    !managedUserGroupIdentityMatches(group) ||
    userGroupRemovalWouldEmptyMembership(group)
  ) {
    return null;
  }
  const deferredChannelAdditionIds = new Set(
    group.channelAdditions.map(({ id }) => id),
  );
  const currentChannelIds = group.desiredChannelIds.filter(
    (channelId) => !deferredChannelAdditionIds.has(channelId),
  );
  return {
    ...group,
    channelAdditions: [],
    channelRemovals: [],
    desiredChannelIds: currentChannelIds,
    desiredUserIds: mergeUniqueStrings(
      group.desiredUserIds,
      group.memberRemovals.map(({ slackUserId }) => slackUserId),
    ),
    effectiveAccessAdditions: group.effectiveAccessAdditions.filter(
      ({ channelId }) => currentChannelIds.includes(channelId),
    ),
    memberRemovals: [],
    requiredChannelIds: currentChannelIds,
  };
}

function selectSingleAuthoritativeRemoval(
  group: SlackUserGroupReconciliation,
  config: OrgChannelSyncConfig,
  allowRemovals: boolean,
): SlackUserGroupReconciliation {
  if (
    !allowRemovals ||
    !managedUserGroupIdentityMatches(group) ||
    userGroupRemovalCount(group) === 0 ||
    config.maxAutomaticRemovals <= 0
  ) {
    return group;
  }
  const [channelRemoval, ...deferredChannelRemovals] = group.channelRemovals;
  if (channelRemoval !== undefined) {
    return {
      ...group,
      channelRemovals: [channelRemoval],
      desiredChannelIds: mergeUniqueStrings(
        group.desiredChannelIds,
        deferredChannelRemovals.map(({ id }) => id),
      ).toSorted((left, right) => left.localeCompare(right)),
      desiredUserIds: mergeUniqueStrings(
        group.desiredUserIds.filter(
          (slackUserId) =>
            !group.memberAdditions.some(
              (item) => item.slackUserId === slackUserId,
            ),
        ),
        group.memberRemovals.map(({ slackUserId }) => slackUserId),
      ).toSorted((left, right) => left.localeCompare(right)),
      effectiveAccessAdditions: [],
      memberAdditions: [],
      memberRemovals: [],
    };
  }
  const [memberRemoval] = group.memberRemovals;
  if (memberRemoval === undefined) return group;
  const channelAdditionIds = new Set(
    group.channelAdditions.map(({ id }) => id),
  );
  const currentChannelIds = mergeUniqueStrings(
    group.desiredChannelIds.filter(
      (channelId) => !channelAdditionIds.has(channelId),
    ),
    group.channelRemovals.map(({ id }) => id),
  ).toSorted((left, right) => left.localeCompare(right));
  const selectedRemovalId = memberRemoval.slackUserId;
  return {
    ...group,
    channelAdditions: [],
    channelRemovals: [],
    desiredChannelIds: currentChannelIds,
    desiredUserIds: plannedCurrentUserIds(group).filter(
      (userId) => userId !== selectedRemovalId,
    ),
    effectiveAccessAdditions: [],
    memberAdditions: [],
    memberRemovals: [memberRemoval],
    requiredChannelIds: currentChannelIds,
  };
}

function limitAdditionBatch(
  group: SlackUserGroupReconciliation,
): SlackUserGroupReconciliation {
  if (
    !membershipAdditionCandidateOnly(group) ||
    group.memberAdditions.length <= MAX_IDENTITIES_PER_USER_GROUP_WRITE
  ) {
    return group;
  }
  const memberAdditions = group.memberAdditions.slice(
    0,
    MAX_IDENTITIES_PER_USER_GROUP_WRITE,
  );
  const selectedUserIds = new Set(
    memberAdditions.map(({ slackUserId }) => slackUserId),
  );
  const deferredUserIds = new Set(
    group.memberAdditions
      .slice(MAX_IDENTITIES_PER_USER_GROUP_WRITE)
      .map(({ slackUserId }) => slackUserId),
  );
  return {
    ...group,
    desiredUserIds: group.desiredUserIds.filter(
      (slackUserId) => !deferredUserIds.has(slackUserId),
    ),
    effectiveAccessAdditions: group.effectiveAccessAdditions.filter(
      ({ slackUserId }) => selectedUserIds.has(slackUserId),
    ),
    memberAdditions,
  };
}

function contractorOnlyMemberRemovalCandidate(
  group: SlackUserGroupReconciliation,
  contractorIds: ReadonlySet<string>,
): null | SlackUserGroupReconciliation {
  if (group.memberRemovals.length === 0) return group;
  const directContractorAuthority =
    group.authority.kind === "google_group" &&
    group.authority.email === contractorAuthorityGroup().email &&
    group.authority.id === contractorAuthorityGroup().id &&
    group.automationOwnership.kind !== "legacy_unmanaged" &&
    group.automationOwnership.sourceGoogleGroupIds.includes(
      contractorAuthorityGroup().id,
    );
  const memberRemovals = group.memberRemovals.filter(
    ({ slackUserId }) =>
      directContractorAuthority || contractorIds.has(slackUserId),
  );
  if (memberRemovals.length === 0) return null;
  const selectedRemovalIds = new Set(
    memberRemovals.map(({ slackUserId }) => slackUserId),
  );
  const deferredUserIds = group.memberRemovals
    .filter(({ slackUserId }) => !selectedRemovalIds.has(slackUserId))
    .map(({ slackUserId }) => slackUserId);
  return {
    ...group,
    desiredUserIds: mergeUniqueStrings(
      group.desiredUserIds,
      deferredUserIds,
    ).toSorted((left, right) => left.localeCompare(right)),
    memberRemovalAuthority: "contractor_group_authoritative",
    memberRemovals,
  };
}

function userGroupCandidateIsExecutable(
  group: SlackUserGroupReconciliation,
  config: OrgChannelSyncConfig,
  allowRemovals: boolean,
): boolean {
  if (group.automationOwnership.kind === "legacy_unmanaged") return false;
  if (group.automationOwnership.kind === "automation_bootstrap") {
    return bootstrapUserGroupCandidateIsExecutable(group);
  }
  if (
    !managedUserGroupIdentityMatches(group) &&
    !selectedChannelRemovalIdentityMatches(group) &&
    !selectedMembershipRemovalIdentityMatches(group) &&
    !membershipAdditionCandidateOnly(group)
  )
    return false;
  if (userGroupRemovalWouldEmptyMembership(group)) return false;
  const additions =
    group.memberAdditions.length + group.effectiveAccessAdditions.length;
  const removals = userGroupRemovalCount(group);
  if (
    containsBlockedEmployeeRemoval(group) ||
    additions > config.maxAutomaticAdditions
  )
    return false;
  if (additions > 0 && removals > 0) return false;
  if (removals === 0) return true;
  if (
    !supportedAutomaticRemovalCandidateOnly(group) ||
    userGroupRemovalProvenanceError([group])
  )
    return false;
  if (
    group.memberRemovals.length > 0 &&
    !automaticMemberRemovalIdentityIsAllowed(group, config)
  )
    return false;
  return allowRemovals && removalLimitForGroup(group, config) > 0;
}

function selectedMembershipRemovalIdentityMatches(
  group: SlackUserGroupReconciliation,
): boolean {
  if (
    !contractorRemovalCandidateOnly(group) &&
    !googleGroupRemovalCandidateOnly(group)
  )
    return false;
  if (
    group.automationOwnership.kind !== "automation_created" &&
    group.automationOwnership.kind !== "explicitly_adopted"
  ) {
    return false;
  }
  return (
    group.expectedSlackUserGroupId !== null &&
    group.slackUserGroupId === group.expectedSlackUserGroupId &&
    sameStrings(group.desiredChannelIds, group.requiredChannelIds) &&
    stringsAreSubset(
      group.requiredChannelIds,
      group.automationOwnership.allowedChannelIds,
    ) &&
    ownershipMatchesGoogleAuthority(group)
  );
}

function containsBlockedEmployeeRemoval(
  group: SlackUserGroupReconciliation,
): boolean {
  return (
    group.memberRemovalAuthority !== "contractor_group_authoritative" &&
    group.memberRemovals.some((member) =>
      isEmployeeEntitlementExcluded(member.identity),
    )
  );
}

function automaticMemberRemovalIdentityIsAllowed(
  group: SlackUserGroupReconciliation,
  config: OrgChannelSyncConfig,
): boolean {
  const scope = config.automaticMemberRemovalScope;
  if (scope.kind === "none") return false;
  if (scope.kind === "all_managed") return true;
  return (
    group.slackUserGroupId !== null &&
    scope.slackUserGroupIds.includes(group.slackUserGroupId)
  );
}

function bootstrapUserGroupCandidateIsExecutable(
  group: SlackUserGroupReconciliation,
): boolean {
  if (group.automationOwnership.kind !== "automation_bootstrap") return false;
  return (
    group.status === "create" &&
    group.slackUserGroupId === null &&
    group.memberRemovals.length === 0 &&
    group.channelRemovals.length === 0 &&
    stringsAreSubset(
      group.requiredChannelIds,
      group.automationOwnership.allowedChannelIds,
    ) &&
    sameStrings(
      group.desiredChannelIds,
      group.automationOwnership.allowedChannelIds,
    ) &&
    ownershipMatchesGoogleAuthority(group)
  );
}

function managedUserGroupIdentityMatches(
  group: SlackUserGroupReconciliation,
): boolean {
  if (
    group.automationOwnership.kind !== "automation_created" &&
    group.automationOwnership.kind !== "explicitly_adopted"
  ) {
    return false;
  }
  return (
    group.expectedSlackUserGroupId !== null &&
    group.slackUserGroupId === group.expectedSlackUserGroupId &&
    stringsAreSubset(
      group.requiredChannelIds,
      group.automationOwnership.allowedChannelIds,
    ) &&
    sameStrings(
      group.desiredChannelIds,
      group.automationOwnership.allowedChannelIds,
    ) &&
    ownershipMatchesGoogleAuthority(group)
  );
}

function selectedChannelRemovalIdentityMatches(
  group: SlackUserGroupReconciliation,
): boolean {
  if (!channelAssociationRemovalCandidateOnly(group)) return false;
  if (
    group.automationOwnership.kind !== "automation_created" &&
    group.automationOwnership.kind !== "explicitly_adopted"
  ) {
    return false;
  }
  const allowedChannelIds = group.automationOwnership.allowedChannelIds;
  return (
    group.expectedSlackUserGroupId !== null &&
    group.slackUserGroupId === group.expectedSlackUserGroupId &&
    sameStrings(group.requiredChannelIds, allowedChannelIds) &&
    group.channelRemovals.every(({ id }) => !allowedChannelIds.includes(id)) &&
    ownershipMatchesGoogleAuthority(group)
  );
}

function appendUserGroupSelectionWarnings(
  plan: OrgChannelPlan,
  config: OrgChannelSyncConfig,
  allowRemovals: boolean,
): void {
  for (const group of plan.userGroups) {
    if (group.status === "in_sync") continue;
    const additions =
      group.memberAdditions.length + group.effectiveAccessAdditions.length;
    const removals = userGroupRemovalCount(group);
    const reason = userGroupDeferralReason(
      group,
      additions,
      removals,
      config,
      allowRemovals,
    );
    if (reason)
      plan.warnings.push(
        `Slack user group @${group.handle} deferred: ${reason}`,
      );
  }
}

function appendSelectedContractorRemainderWarnings(
  plan: OrgChannelPlan,
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
  config: OrgChannelSyncConfig,
): void {
  const contractorIds = new Set(
    plan.lifecycle.allTeamProjection?.excludedFromSourceMembers.map(
      ({ slackUserId }) => slackUserId,
    ),
  );
  const removalLimit = config.maxAutomaticContractorRemovals ?? 0;
  for (const selected of selectedUserGroups) {
    if (selected.memberRemovalAuthority !== "contractor_group_authoritative")
      continue;
    const original = plan.userGroups.find(
      ({ handle }) => handle === selected.handle,
    );
    const contractorRemovalCount =
      original?.memberRemovals.filter(({ slackUserId }) =>
        contractorIds.has(slackUserId),
      ).length ?? 0;
    if (contractorRemovalCount <= selected.memberRemovals.length) continue;
    const warning = `Slack user group @${selected.handle} deferred: only ${String(removalLimit)} reviewed authoritative removal can run per execution`;
    if (!plan.warnings.includes(warning)) plan.warnings.push(warning);
  }
}

function appendSelectedAdditionRemainderWarnings(
  plan: OrgChannelPlan,
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
): void {
  for (const selected of selectedUserGroups) {
    const original = plan.userGroups.find(
      ({ handle }) => handle === selected.handle,
    );
    const deferred =
      (original?.memberAdditions.length ?? 0) - selected.memberAdditions.length;
    if (deferred <= 0) continue;
    plan.warnings.push(
      `Slack user group @${selected.handle} deferred: ${String(deferred)} additional Google-authoritative ${deferred === 1 ? "identity remains" : "identities remain"} for later reconciliation`,
    );
  }
}

function appendProtectedAdditionWarnings(
  plan: OrgChannelPlan,
  protectedSlackUserIds: readonly string[] | undefined,
): void {
  const protectedIds = new Set(protectedSlackUserIds);
  for (const group of plan.userGroups) {
    if (
      !group.memberAdditions.some(({ slackUserId }) =>
        protectedIds.has(slackUserId),
      )
    )
      continue;
    plan.warnings.push(
      `Slack user group @${group.handle} deferred: protected identities require a reviewed signed plan`,
    );
  }
}

function userGroupDeferralReason(
  group: SlackUserGroupReconciliation,
  additions: number,
  removals: number,
  config: OrgChannelSyncConfig,
  allowRemovals: boolean,
): null | string {
  const ownershipReason = userGroupOwnershipDeferralReason(group);
  if (ownershipReason) return ownershipReason;
  const changeReason = userGroupChangeDeferralReason(
    group,
    additions,
    removals,
    config,
  );
  if (changeReason) return changeReason;
  return userGroupRemovalLimitDeferralReason(
    group,
    removals,
    config,
    allowRemovals,
  );
}

function userGroupOwnershipDeferralReason(
  group: SlackUserGroupReconciliation,
): null | string {
  if (group.automationOwnership.kind === "legacy_unmanaged") {
    return "the immutable group is legacy-unmanaged and frozen against automation writes";
  }
  if (
    group.automationOwnership.kind === "automation_bootstrap" &&
    (group.status !== "create" || group.slackUserGroupId !== null)
  ) {
    return "bootstrap ownership permits creation only; pin the returned immutable ID before updates";
  }
  if (!ownershipMatchesGoogleAuthority(group)) {
    return "automation ownership manifest does not exactly match the immutable Google group authority";
  }
  if (
    group.automationOwnership.kind !== "automation_bootstrap" &&
    !managedUserGroupIdentityMatches(group)
  ) {
    return "automation ownership manifest does not exactly match the live immutable group and channel allowlist";
  }
  return null;
}

function userGroupChangeDeferralReason(
  group: SlackUserGroupReconciliation,
  additions: number,
  removals: number,
  config: OrgChannelSyncConfig,
): null | string {
  if (userGroupRemovalWouldEmptyMembership(group)) {
    return "the reviewed removal would leave the Slack user group empty";
  }
  if (additions > config.maxAutomaticAdditions)
    return "addition count exceeds the safety limit";
  if (additions > 0 && removals > 0)
    return "additions and removals require separate plans";
  if (removals > 0 && !supportedAutomaticRemovalCandidateOnly(group)) {
    return "only single-authority Google-group or contractor member removals are eligible for automatic writes";
  }
  const provenanceError = userGroupRemovalProvenanceError([group]);
  if (removals > 0 && provenanceError) {
    return provenanceError.replace("Safety stop: ", "");
  }
  if (
    removals > 0 &&
    supportedAutomaticRemovalCandidateOnly(group) &&
    !automaticMemberRemovalIdentityIsAllowed(group, config)
  ) {
    return "the immutable Slack user group is not allowlisted for automatic member removals";
  }
  return null;
}

function userGroupRemovalLimitDeferralReason(
  group: SlackUserGroupReconciliation,
  removals: number,
  config: OrgChannelSyncConfig,
  allowRemovals: boolean,
): null | string {
  const removalLimit = removalLimitForGroup(group, config);
  if (
    supportedAutomaticRemovalCandidateOnly(group) &&
    removals > removalLimit &&
    removalLimit > 0
  ) {
    return `only ${String(removalLimit)} reviewed authoritative removal can run per execution`;
  }
  if (removals > removalLimit) return "removal count exceeds the safety limit";
  if (removals > 0 && !allowRemovals)
    return "the independent removal gate is disabled";
  return null;
}

function userGroupWriteCapabilityUnavailable(
  slack: IOrgChannelSlackClient,
  removalOnly: boolean,
  additionOnly: boolean,
  bootstrap: boolean,
): boolean {
  if (!slack.getUserGroup) return true;
  if (removalOnly)
    return !slack.removeUserGroupMembers || !slack.getUserGroupById;
  if (additionOnly)
    return !slack.addUserGroupMembers || !slack.getUserGroupById;
  if (bootstrap) return !slack.createUserGroup;
  return !slack.updateUserGroup;
}

function membershipAdditionCandidateOnly(
  group: SlackUserGroupReconciliation,
): boolean {
  if (
    group.automationOwnership.kind !== "automation_created" &&
    group.automationOwnership.kind !== "explicitly_adopted"
  ) {
    return false;
  }
  const allowedChannelIds = group.automationOwnership.allowedChannelIds;
  return (
    group.slackUserGroupId !== null &&
    group.status === "update" &&
    group.currentHandle === group.handle &&
    group.currentName === group.desiredName &&
    group.memberAdditions.length > 0 &&
    group.memberRemovals.length === 0 &&
    group.channelAdditions.length === 0 &&
    group.channelRemovals.length === 0 &&
    sameStrings(group.desiredChannelIds, group.requiredChannelIds) &&
    stringsAreSubset(group.requiredChannelIds, allowedChannelIds) &&
    ownershipMatchesGoogleAuthority(group) &&
    group.memberAdditions.every(({ slackUserId }) =>
      group.effectiveAccessAdditions.every(
        (access) =>
          access.slackUserId !== slackUserId ||
          (group.requiredChannelIds.includes(access.channelId) &&
            allowedChannelIds.includes(access.channelId)),
      ),
    ) &&
    group.effectiveAccessAdditions.every(({ slackUserId }) =>
      group.memberAdditions.some(
        (addition) => addition.slackUserId === slackUserId,
      ),
    )
  );
}

function userGroupRemovalWouldEmptyMembership(
  group: SlackUserGroupReconciliation,
): boolean {
  return group.memberRemovals.length > 0 && group.desiredUserIds.length === 0;
}

function ownershipMatchesGoogleAuthority(
  group: SlackUserGroupReconciliation,
): boolean {
  if (group.automationOwnership.kind === "legacy_unmanaged") return false;
  const sourceIds =
    group.authority.kind === "google_group"
      ? [group.authority.id]
      : group.authority.ids;
  const excludedIds =
    group.authority.kind === "google_group_union"
      ? group.authority.excludedIds
      : (group.authority.excludedIds ?? []);
  return (
    sameStrings(sourceIds, group.automationOwnership.sourceGoogleGroupIds) &&
    sameStrings(excludedIds, group.automationOwnership.excludedGoogleGroupIds)
  );
}

function limitRemovalBatch(
  group: SlackUserGroupReconciliation,
  removalLimit: number,
): SlackUserGroupReconciliation {
  if (
    !supportedAutomaticRemovalCandidateOnly(group) ||
    removalLimit <= 0 ||
    group.memberRemovals.length <= removalLimit
  ) {
    return group;
  }
  const memberRemovals = group.memberRemovals.slice(0, removalLimit);
  const deferredUserIds = group.memberRemovals
    .slice(removalLimit)
    .map(({ slackUserId }) => slackUserId);
  return {
    ...group,
    desiredUserIds: mergeUniqueStrings(
      group.desiredUserIds,
      deferredUserIds,
    ).toSorted((left, right) => left.localeCompare(right)),
    memberRemovals,
  };
}

function compareUserGroupRolloutPriority(
  left: SlackUserGroupReconciliation,
  right: SlackUserGroupReconciliation,
): number {
  const rank = { "canonical_team": 0, "workspace_union": 1 } as const;
  return (
    rank[left.rolloutPriority] - rank[right.rolloutPriority] ||
    SLACK_USER_GROUP_OWNERSHIP_RANK[left.automationOwnership.kind] -
      SLACK_USER_GROUP_OWNERSHIP_RANK[right.automationOwnership.kind] ||
    userGroupRemovalCount(left) - userGroupRemovalCount(right) ||
    left.effectiveAccessAdditions.length -
      right.effectiveAccessAdditions.length ||
    left.memberAdditions.length - right.memberAdditions.length ||
    left.channelAdditions.length - right.channelAdditions.length ||
    Number(left.status === "create") - Number(right.status === "create") ||
    left.handle.localeCompare(right.handle)
  );
}

function userGroupRemovalCount(group: SlackUserGroupReconciliation): number {
  return group.memberRemovals.length + group.channelRemovals.length;
}

function liveCapabilityError(
  plan: OrgChannelPlan,
  selectedChannelAdditions: readonly ChannelMembershipChange[],
  selectedUserGroupHandles: readonly string[],
  selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
  scopes: readonly string[],
  selectedChannelRename: ChannelRenameChange | null,
): null | string {
  const scopeSet = new Set(scopes);
  if (
    selectedProvenanceChannelRemovals.length > 0 &&
    (!scopeSet.has("groups:write") || !scopeSet.has("groups:read"))
  ) {
    return "Slack token lacks private-channel read/write scope for provenance removals";
  }
  if (
    selectedUserGroupHandles.length === 0 &&
    selectedChannelAdditions.length === 0 &&
    selectedProvenanceChannelRemovals.length === 0 &&
    selectedChannelRename === null &&
    (plan.additions.length > 0 || plan.removals.length > 0)
  ) {
    return "Direct Slack channel membership writes are disabled; use Slack user groups";
  }
  if (
    selectedChannelAdditions.some(
      (change) =>
        !scopeSet.has(
          change.isPrivate ? "groups:write.invites" : "channels:write.invites",
        ),
    )
  ) {
    return "Slack token lacks the matching channel invitation scope";
  }
  if (
    selectedUserGroupHandles.length > 0 &&
    !scopeSet.has("usergroups:write")
  ) {
    return "Slack token lacks usergroups:write for user-group reconciliation";
  }
  if (
    selectedChannelRename?.isPrivate === false &&
    !scopeSet.has("channels:write")
  ) {
    return "Slack token lacks channels:write for public-channel renames";
  }
  if (
    selectedChannelRename?.isPrivate === true &&
    !scopeSet.has("groups:write")
  ) {
    return "Slack token lacks groups:write for private-channel renames";
  }
  return null;
}

function selectChannelRenameForWrite(
  plan: OrgChannelPlan,
  scopes: readonly string[],
  writeLimit: number,
): ChannelRenameChange | null {
  if (writeLimit < 1) return null;
  return (
    plan.channelRenames.find((rename) => canRenameChannel(rename, scopes)) ??
    null
  );
}

function canRenameChannel(
  rename: ChannelRenameChange,
  scopes: readonly string[],
): boolean {
  const requiredScope = rename.isPrivate ? "groups:write" : "channels:write";
  return scopes.includes(requiredScope);
}

async function hashPlan(
  plan: OrgChannelPlan,
  selectedChannelAdditions: readonly ChannelMembershipChange[],
  selectedUserGroups: readonly SlackUserGroupReconciliation[],
  selectedChannelRename: ChannelRenameChange | null,
  selectedProvenanceChannelRemovals: readonly ChannelMembershipRemovalPlan[],
): Promise<string> {
  const canonical = JSON.stringify({
    additions: plan.additions,
    channelRenames: plan.channelRenames,
    managerTargets: plan.managerTargets,
    removals: plan.removals,
    selectedChannelAdditions,
    selectedChannelRename,
    selectedProvenanceChannelRemovals,
    selectedUserGroups,
    selectionPolicyVersion: USER_GROUP_SELECTION_POLICY_VERSION,
    userGroups: plan.userGroups,
  });
  return sha256(canonical);
}

function reportWithError(
  report: OrgChannelSyncRunReport,
  error: string,
): OrgChannelSyncRunReport {
  return { ...report, errors: [...report.errors, error] };
}

function finishReport(
  report: OrgChannelSyncRunReport,
): OrgChannelSyncRunReport {
  logEvent("org_channel_sync.completed", {
    additions: report.additions.length,
    "channel_renames_planned": report.channelRenames.length,
    "duration_ms": report.durationMs,
    errors: report.errors.length,
    removals: report.removals.length,
    "run_id": report.runId,
    "selected_user_group_handles": report.selectedUserGroupHandles.join(","),
    "selected_user_group_removals": report.selectedUserGroups
      .flatMap((group) =>
        group.memberRemovals.map(({ slackUserId }) => slackUserId),
      )
      .join(","),
    "selection_policy_version": report.selectionPolicyVersion,
    status: report.status,
    "user_group_changes": report.userGroups.filter(
      (group) => group.status !== "in_sync",
    ).length,
    warnings: report.warnings.length,
    writes: report.writes,
  });
  return report;
}

function ensureWriteBudget(deadlineAt: number): void {
  if (!hasWriteBudget(deadlineAt)) {
    throw new Error(
      "Org channel sync stopped before writes because its deadline is too close",
    );
  }
}

function hasWriteBudget(deadlineAt: number): boolean {
  return Date.now() + WRITE_SAFETY_MARGIN_MS < deadlineAt;
}

function selectAutomaticChannelAdditions(
  plan: OrgChannelPlan,
  selectedChannelRename: ChannelRenameChange | null,
  limit: number,
): ChannelMembershipChange[] {
  const selected =
    selectedChannelRename === null ? plan.additions.slice(0, limit) : [];
  const deferred = plan.additions.length - selected.length;
  if (deferred > 0) {
    plan.warnings.push(
      `${String(deferred)} direct channel membership additions deferred by the per-run safety ceiling`,
    );
  }
  return selected;
}

function isolateChannelInvitationWork(
  selectedChannelAdditions: readonly ChannelMembershipChange[],
  selectedUserGroups: SlackUserGroupReconciliation[],
  selectedProvenanceChannelRemovals: ChannelMembershipRemovalPlan[],
): {
  selectedProvenanceChannelRemovals: ChannelMembershipRemovalPlan[];
  selectedUserGroups: SlackUserGroupReconciliation[];
} {
  if (selectedChannelAdditions.length === 0) {
    return { selectedProvenanceChannelRemovals, selectedUserGroups };
  }
  return { selectedProvenanceChannelRemovals: [], selectedUserGroups: [] };
}

function sameUserGroupPlan(
  current: SlackUserGroupReconciliation,
  expected: SlackUserGroupReconciliation,
): boolean {
  return [
    sameUserGroupAuthority(current, expected),
    sameAutomationOwnership(
      current.automationOwnership,
      expected.automationOwnership,
    ),
    sameArray(
      current.channelAdditions,
      expected.channelAdditions,
      sameSlackChannelIdentity,
    ),
    current.channelMembershipMode === expected.channelMembershipMode,
    sameArray(
      current.channelRemovals,
      expected.channelRemovals,
      sameSlackChannelIdentity,
    ),
    current.currentHandle === expected.currentHandle,
    current.currentName === expected.currentName,
    sameStrings(current.desiredChannelIds, expected.desiredChannelIds),
    current.desiredName === expected.desiredName,
    sameStrings(current.desiredUserIds, expected.desiredUserIds),
    sameArray(
      current.effectiveAccessAdditions,
      expected.effectiveAccessAdditions,
      sameChannelMembership,
    ),
    current.expectedSlackUserGroupId === expected.expectedSlackUserGroupId,
    current.handle === expected.handle,
    sameArray(
      current.memberAdditions,
      expected.memberAdditions,
      sameMemberChange,
    ),
    current.memberRemovalAuthority === expected.memberRemovalAuthority,
    sameArray(
      current.memberRemovals,
      expected.memberRemovals,
      sameMemberChange,
    ),
    current.membershipMode === expected.membershipMode,
    sameStrings(current.requiredChannelIds, expected.requiredChannelIds),
    current.rolloutPriority === expected.rolloutPriority,
    current.slackUserGroupId === expected.slackUserGroupId,
    current.status === expected.status,
  ].every(Boolean);
}

function sameStrings(
  current: readonly string[],
  expected: readonly string[],
): boolean {
  const currentSorted = current.toSorted();
  const expectedSorted = expected.toSorted();
  return (
    currentSorted.length === expectedSorted.length &&
    currentSorted.every((value, index) => value === expectedSorted[index])
  );
}

function sameChannelMembership(
  current: ChannelMembershipChange,
  expected: ChannelMembershipChange,
): boolean {
  return [
    current.channelId === expected.channelId,
    current.channelName === expected.channelName,
    current.identity === expected.identity,
    current.isPrivate === expected.isPrivate,
    current.removalAuthority === expected.removalAuthority,
    current.slackUserId === expected.slackUserId,
  ].every(Boolean);
}

function sameChannelIdentity(
  current: SlackChannelIdentity,
  expected: ChannelMembershipChange,
): boolean {
  return (
    current.id === expected.channelId &&
    current.name === expected.channelName &&
    !current.isArchived &&
    current.isPrivate === expected.isPrivate
  );
}

function sameSlackChannelIdentity(
  current: SlackChannelIdentity,
  expected: SlackChannelIdentity,
): boolean {
  return [
    current.id === expected.id,
    current.name === expected.name,
    current.isArchived === expected.isArchived,
    current.isPrivate === expected.isPrivate,
  ].every(Boolean);
}

function sameMemberChange(
  current: { identity: string; slackUserId: string },
  expected: { identity: string; slackUserId: string },
): boolean {
  return (
    current.identity === expected.identity &&
    current.slackUserId === expected.slackUserId
  );
}

function sameArray<T extends object>(
  current: readonly T[],
  expected: readonly T[],
  predicate: (currentValue: T, expectedValue: T) => boolean,
): boolean {
  if (current.length !== expected.length) return false;
  return current.every((value, index) => {
    const expectedValue = expected.at(index);
    return expectedValue !== undefined && predicate(value, expectedValue);
  });
}

function sameUserGroupAuthority(
  current: SlackUserGroupReconciliation,
  expected: SlackUserGroupReconciliation,
): boolean {
  const left = current.authority;
  const right = expected.authority;
  if (left.kind !== right.kind) return false;
  if (left.kind === "google_group" && right.kind === "google_group") {
    return [
      left.email === right.email,
      left.id === right.id,
      sameStrings(left.excludedEmails ?? [], right.excludedEmails ?? []),
      sameStrings(left.excludedIds ?? [], right.excludedIds ?? []),
    ].every(Boolean);
  }
  if (left.kind !== "google_group_union" || right.kind !== "google_group_union")
    return false;
  return [
    sameStrings(left.emails, right.emails),
    sameStrings(left.ids, right.ids),
    sameStrings(left.excludedEmails, right.excludedEmails),
    sameStrings(left.excludedIds, right.excludedIds),
  ].every(Boolean);
}

function sameAutomationOwnership(
  current: SlackUserGroupReconciliation["automationOwnership"],
  expected: SlackUserGroupReconciliation["automationOwnership"],
): boolean {
  if (current.kind !== expected.kind) return false;
  if (
    current.kind === "legacy_unmanaged" ||
    expected.kind === "legacy_unmanaged"
  )
    return true;
  const commonMatches = [
    sameStrings(current.allowedChannelIds, expected.allowedChannelIds),
    current.evidenceDigest === expected.evidenceDigest,
    sameStrings(
      current.excludedGoogleGroupIds,
      expected.excludedGoogleGroupIds,
    ),
    sameStrings(current.sourceGoogleGroupIds, expected.sourceGoogleGroupIds),
  ].every(Boolean);
  if (!commonMatches) return false;
  if (
    current.kind === "automation_bootstrap" ||
    expected.kind === "automation_bootstrap"
  )
    return true;
  return current.cutoverRevision === expected.cutoverRevision;
}

function stringsAreSubset(
  required: readonly string[],
  allowed: readonly string[],
): boolean {
  const allowedValues = new Set(allowed);
  return required.every((value) => allowedValues.has(value));
}

function buildUserGroupWriteState(
  expected: SlackUserGroupReconciliation,
  current: null | SlackUserGroupSnapshot,
): { channelIds: string[]; userIds: string[] } {
  const channelIds =
    expected.channelMembershipMode === "additive"
      ? mergeUniqueStrings(
          expected.desiredChannelIds,
          current?.channelIds ?? [],
        ).toSorted((left, right) => left.localeCompare(right))
      : expected.desiredChannelIds;
  const userIds =
    effectiveMembershipWriteMode(expected) === "additive"
      ? mergeUniqueStrings(
          expected.desiredUserIds,
          current?.userIds ?? [],
        ).toSorted((left, right) => left.localeCompare(right))
      : expected.desiredUserIds;
  return { channelIds, userIds };
}

async function listEligibleProvenanceCandidates(
  repository: ChannelMembershipProvenanceRepository | undefined,
  contractorSlackUserIds: ReadonlySet<string>,
  protectedSlackUserIds: ReadonlySet<string>,
  contractorOnlyMemberRemovals: boolean,
): Promise<{
  eligibleCandidates: ChannelMembershipRemovalCandidate[];
  repositoryCandidates: ChannelMembershipRemovalCandidate[];
}> {
  if (!repository) return { eligibleCandidates: [], repositoryCandidates: [] };
  const repositoryCandidates = await repository.listExclusiveReleasedCandidates(
    100,
    contractorOnlyMemberRemovals ? [...contractorSlackUserIds] : undefined,
  );
  const eligibleCandidates = contractorOnlyMemberRemovals
    ? repositoryCandidates.filter(
        ({ slackUserId }) =>
          contractorSlackUserIds.has(slackUserId) &&
          !protectedSlackUserIds.has(slackUserId),
      )
    : repositoryCandidates;
  return { eligibleCandidates, repositoryCandidates };
}

function plannedCurrentUserIds(
  expected: SlackUserGroupReconciliation,
): string[] {
  const additions = new Set(
    expected.memberAdditions.map(({ slackUserId }) => slackUserId),
  );
  return mergeUniqueStrings(
    expected.desiredUserIds.filter((userId) => !additions.has(userId)),
    expected.memberRemovals.map(({ slackUserId }) => slackUserId),
  ).toSorted((left, right) => left.localeCompare(right));
}

function plannedCurrentChannelIds(
  expected: SlackUserGroupReconciliation,
): string[] {
  const additions = new Set(expected.channelAdditions.map(({ id }) => id));
  return mergeUniqueStrings(
    expected.desiredChannelIds.filter((channelId) => !additions.has(channelId)),
    expected.channelRemovals.map(({ id }) => id),
  ).toSorted((left, right) => left.localeCompare(right));
}

function verifyUserGroupReadback(
  expected: SlackUserGroupReconciliation,
  actual: null | SlackUserGroupSnapshot,
  userGroupId: string,
  channelIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This boundary compares raw signed-plan IDs with provider snapshot IDs; each resource role is checked independently below.
  userIds: readonly string[],
): void {
  const membersConverged =
    effectiveMembershipWriteMode(expected) === "additive" ||
    expected.memberRemovals.length > 0
      ? containsAll(actual?.userIds ?? [], userIds) &&
        excludesAll(
          actual?.userIds ?? [],
          expected.memberRemovals.map(({ slackUserId }) => slackUserId),
        )
      : sameStrings(actual?.userIds ?? [], userIds);
  if (actual?.id !== userGroupId || !membersConverged) {
    throw new Error(
      `Slack user-group member read-back failed for @${expected.handle}`,
    );
  }
  const channelsConverged =
    expected.channelMembershipMode === "additive"
      ? containsAll(actual.channelIds, channelIds)
      : sameStrings(actual.channelIds, channelIds);
  if (!channelsConverged) {
    throw new Error(
      `Slack user-group channel read-back failed for @${expected.handle}`,
    );
  }
}

function effectiveMembershipWriteMode(
  expected: SlackUserGroupReconciliation,
): "additive" | "authoritative" {
  return expected.memberRemovals.length > 0
    ? "authoritative"
    : expected.membershipMode;
}

function containsAll(
  current: readonly string[],
  expected: readonly string[],
): boolean {
  const currentSet = new Set(current);
  return expected.every((value) => currentSet.has(value));
}

function excludesAll(
  current: readonly string[],
  excluded: readonly string[],
): boolean {
  const currentSet = new Set(current);
  return excluded.every((value) => !currentSet.has(value));
}

function mergeUniqueStrings(
  existing: readonly string[],
  required: readonly string[],
): string[] {
  const result = new Set(existing);
  for (const value of required) result.add(value);
  return result.values().toArray();
}

function logUserGroupWrite(
  phase: "ambiguous_recovered" | "started" | "verified",
  group: SlackUserGroupReconciliation,
  runId: string,
): void {
  logMutationCounter(
    "user_group_write",
    phase === "started" ? "attempted" : phase,
    runId,
  );
  logEvent("org_channel_sync.user_group_write", {
    authority: group.authority.kind,
    "google_group_email":
      group.authority.kind === "google_group"
        ? group.authority.email
        : undefined,
    "google_group_emails":
      group.authority.kind === "google_group_union"
        ? group.authority.emails.join(",")
        : undefined,
    handle: group.handle,
    phase,
    "run_id": runId,
    status: group.status,
  });
}

function logMutationCounter(
  operation: "channel_invite" | "channel_rename" | "user_group_write",
  outcome:
    | "ambiguous_recovered"
    | "attempted"
    | "failed"
    | "started"
    | "verified",
  runId: string,
): void {
  logEvent("org_channel_sync.mutation_counter", {
    operation,
    outcome,
    "run_id": runId,
    value: 1,
  });
}

function logChannelInvitation(
  phase: "failed" | "started" | "verified",
  change: ChannelMembershipChange,
  runId: string,
): void {
  logMutationCounter(
    "channel_invite",
    phase === "started" ? "attempted" : phase,
    runId,
  );
  logEvent("org_channel_sync.channel_invite", {
    "channel_id": change.channelId,
    "channel_name": change.channelName,
    phase,
    "run_id": runId,
    "slack_user_id": change.slackUserId,
  });
}

function sameRename(
  current: ChannelRenameChange,
  expected: ChannelRenameChange,
): boolean {
  return [
    current.channelId === expected.channelId,
    current.currentName === expected.currentName,
    current.expectedName === expected.expectedName,
    current.isPrivate === expected.isPrivate,
  ].every(Boolean);
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
