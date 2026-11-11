import { JsonValueSchema, type ManagedChange } from "../operations/schemas.ts";
import { WorkspaceDirectoryChangeDetailsSchema } from "./contracts.ts";
import { readWorkspaceObservation } from "./observation-carrier.ts";
import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";

export async function readWorkspaceDirectoryManagedSlice(
  runtime: WorkspaceDirectoryRuntime,
  change: ManagedChange,
) {
  const details = WorkspaceDirectoryChangeDetailsSchema.parse(change.details);
  switch (details.kind) {
    case "sentry-memberships":
      if (runtime.readSentryMembershipsSlice === undefined)
        throw new Error("workspace_sentry_adapter_required");
      return runtime.readSentryMembershipsSlice(details.plan);
    case "pagerduty-teams":
      if (runtime.readPagerDutyTeamsSlice === undefined)
        throw new Error("workspace_pagerduty_teams_adapter_required");
      return runtime.readPagerDutyTeamsSlice(details.plan);
    case "google-group-cleanup":
      if (runtime.readGoogleGroupCleanupSlice === undefined)
        throw new Error("workspace_google_group_cleanup_adapter_required");
      return runtime.readGoogleGroupCleanupSlice(details.plan);
    case "slack-names":
    case "linear-profiles":
      if (runtime.readNameRepairSlice === undefined)
        throw new Error("workspace_directory_name_parent_adapter_unavailable");
      return runtime.readNameRepairSlice(details.plan, details.kind);
    case "trycomp-people":
      return runtime.readTrycompSlice(details.plan);
    case "drive-org-chart":
      return runtime.readDriveOrgChartSlice(details.plan);
    case "fanout": {
      if (details.plan.branches[5].schemaPlan.kind === "not-selected") {
        return readWorkspaceObservation(
          runtime.identityTransitionsExcluded === true,
          change,
        );
      }
      const [githubIdentities, identitySchema] = await Promise.all([
        runtime.readGithubIdentitySeedSlice(details.plan),
        runtime.readIdentitySchemaSlice(),
      ]);
      return JsonValueSchema.parse({ githubIdentities, identitySchema });
    }
    case "github-access":
      return runtime.readGitHubAccessSlice(details.plan);
    case "linear-suspensions":
      return JsonValueSchema.parse(
        await runtime.readAccessGuardLinearSlice(details.actions),
      );
    case "slack-groups-channels":
      return runtime.readSlackGroupsChannelsSlice(details.plan);
    case "slack-profiles":
      return runtime.readSlackProfilesSlice(details.plan);
  }
}
