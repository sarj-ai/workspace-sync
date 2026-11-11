import type { AccessGuardPlan } from "../access-guard/model.ts";
import type { GithubDispatchClaim } from "../identity-provisioning/github-zero-dispatch.ts";
import type { JsonValue } from "../operations/schemas.ts";
import type { ReviewedSlackLifecycleRemoval } from "../org-sync/reviewed-lifecycle-removal.ts";
import type {
  WorkspaceDirectoryPlan,
  WorkspaceDirectoryAuthorizedActionId,
} from "./contracts.ts";
import type { ReviewedGoogleGroupCleanupIntent } from "./reviewed-google-group-cleanup.ts";
import type { ReviewedLinearSuspension } from "./reviewed-linear-suspension.ts";
import type { ReviewedNameAction } from "./reviewed-name-plan.ts";

export interface WorkspaceDirectoryRuntime {
  applyAccessGuard(plan: WorkspaceDirectoryPlan): Promise<string>;
  applyDriveOrgChart(plan: WorkspaceDirectoryPlan): Promise<string>;
  applyGitHubAccess(
    plan: WorkspaceDirectoryPlan,
    githubDispatchClaim?: GithubDispatchClaim,
  ): Promise<string>;
  applyGoogleGroupCleanup?(plan: WorkspaceDirectoryPlan): Promise<string>;
  applyIdentityProvisioning(plan: WorkspaceDirectoryPlan): Promise<string>;
  applyNameRepair?(
    plan: WorkspaceDirectoryPlan,
    branchId: ReviewedNameAction["branchId"],
  ): Promise<string>;
  applyPagerDutyTeams?(plan: WorkspaceDirectoryPlan): Promise<string>;
  applySentryMemberships?(plan: WorkspaceDirectoryPlan): Promise<string>;
  applySlackGroupsChannels(plan: WorkspaceDirectoryPlan): Promise<string>;
  applySlackProfiles(plan: WorkspaceDirectoryPlan): Promise<string>;
  applyTrycomp(plan: WorkspaceDirectoryPlan): Promise<string>;
  capture(
    includedActionIds?: null | readonly WorkspaceDirectoryAuthorizedActionId[],
    reviewedSlackLifecycleRemoval?: ReviewedSlackLifecycleRemoval,
    reviewedLinearSuspension?: ReviewedLinearSuspension,
    reviewedGoogleGroupCleanup?: ReviewedGoogleGroupCleanupIntent,
  ): Promise<WorkspaceDirectoryPlan>;
  readonly identityTransitionsExcluded?: boolean;
  readAccessGuardLinearSlice(
    actions: AccessGuardPlan["actions"],
  ): Promise<JsonValue>;
  readAuthorityFingerprint(): Promise<string>;
  readDriveOrgChartSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readGitHubAccessAuthorityFingerprint(): Promise<null | string>;
  readGitHubAccessSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readGithubIdentitySeedSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readGithubIdentitySourceFingerprint(): Promise<null | string>;
  readGoogleGroupCleanupSlice?(
    plan: WorkspaceDirectoryPlan,
  ): Promise<JsonValue>;
  readIdentitySchemaSlice(): Promise<JsonValue>;
  readNameRepairSlice?(
    plan: WorkspaceDirectoryPlan,
    branchId: ReviewedNameAction["branchId"],
  ): Promise<JsonValue>;
  readNameSourceFingerprint?(
    branchId: ReviewedNameAction["branchId"],
  ): Promise<null | string>;
  readPagerDutyTeamsSlice?(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readSentryMembershipsSlice?(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readSlackGroupsChannelsObservationSlice?(
    plan: WorkspaceDirectoryPlan,
  ): Promise<JsonValue>;
  readSlackGroupsChannelsSlice(
    plan: WorkspaceDirectoryPlan,
  ): Promise<JsonValue>;
  readSlackProfilesSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readTrycompSlice(plan: WorkspaceDirectoryPlan): Promise<JsonValue>;
  readTrycompSourceFingerprint(): Promise<null | string>;
}
