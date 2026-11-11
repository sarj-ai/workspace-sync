import type { AccessGuardService } from "../access-guard/access-guard-service.ts";
import type { WorkspaceSyncPolicy } from "../configuration.ts";
import type { GoogleAccessAuditClient } from "../github-access-audit/google-access-audit-client.ts";
import type { ReviewedGitHubDirectGrantRetention } from "../github-access-audit/reviewed-direct-grants.ts";
import type { GithubAccessAuditService } from "../github-access-audit/service.ts";
import type { EmployeeEntitlementAuthority } from "../identity-provisioning/employee-entitlement-policy.ts";
import type { ResourceLeaseRepository } from "../identity-sync/resource-lease.ts";
import type { OrgChannelSyncService } from "../org-sync/channel-service.ts";
import type {
  DIRECTORY_READONLY_SCOPE,
  GoogleDirectoryClient,
} from "../org-sync/google-directory-client.ts";
import type { GoogleGroupsClient } from "../org-sync/google-groups-client.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type { OrgChartService } from "../org-sync/org-chart-service.ts";
import type { OrgSyncServiceContract } from "../org-sync/service.ts";
import type { ITrycompPeopleSyncService } from "../trycomp/service.ts";
import type { WorkspaceLedgerHistoryIndex } from "../workspace-directory/d1-workspace-ledger-history-index.ts";
import type { PagerDutyTeamSyncSettings } from "../workspace-directory/pagerduty-team-config.ts";
import type { GoogleGroupCleanupServiceContract } from "./google-group-cleanup-service.ts";
import type {
  ILinearProfileReader,
  ILinearProfileWriter,
} from "./linear-profile-service.ts";
import type { PagerDutyTeamExecutionPort } from "./pager-duty-team-service.ts";
import type { SentryWorkspaceExecutionPort } from "./sentry-workspace-service.ts";
import type {
  ISlackNameReader,
  ISlackNameWriter,
} from "./slack-name-service.ts";

export interface WorkspaceNameServices {
  linear: ILinearProfileReader & ILinearProfileWriter;
  slack: ISlackNameReader & ISlackNameWriter;
}

export interface OrgSyncRuntimeConfig {
  approvedPlanHash: string;
  chart: OrgChartService;
  disabled: boolean;
  google: GoogleDirectoryClient;
  mode: "audit" | "live";
  service: OrgSyncServiceContract;
}

export interface OrgChannelSyncRuntime {
  allowRemovals: boolean;
  approvedPlanHash: string;
  disabled: boolean;
  mode: "audit" | "live";
  service: OrgChannelSyncService;
}

export type OrgChannelSyncRuntimeContext =
  | {
      readonly database: D1Database;
      readonly kind: "scheduled";
      readonly leaseRepository: ResourceLeaseRepository;
    }
  | { readonly database?: D1Database; readonly kind: "audit" };

export interface TrycompPeopleSyncRuntime {
  contractorGroupEmail: string;
  google: GoogleDirectoryClient;
  groups: GoogleGroupsClient;
  service: ITrycompPeopleSyncService;
}

export interface GitHubGoogleAuthoritySource {
  google: GoogleAccessAuditClient;
  rootGroupEmail: string;
}

export interface WorkspaceGitHubPolicy {
  reportsLookbackDays: number;
  excludedGroupEmails: readonly string[];
  teamMappings: Readonly<Record<string, string>>;
  teamPins: Readonly<Record<string, number>>;
  unmanagedGithubTeams: readonly string[];
  reviewedTeamMemberships: readonly WorkspaceSyncPolicy["reviewedGitHubTeamMemberships"][number][];
  reviewedDirectGrantRetentions: readonly ReviewedGitHubDirectGrantRetention[];
}

/** Authenticated provider construction stays with the deployment; decisions stay here. */
export interface WorkspaceSyncRuntimeBindings {
  accessGuard(history?: WorkspaceLedgerHistoryIndex): {
    google: GoogleDirectoryClient;
    service: AccessGuardService;
  };
  google(
    operation?: string,
    scope?: typeof DIRECTORY_READONLY_SCOPE,
  ): GoogleDirectoryClient;
  org(lease?: ResourceLeaseRepository): OrgSyncRuntimeConfig;
  channels(context: OrgChannelSyncRuntimeContext): OrgChannelSyncRuntime;
  githubAudit(): GithubAccessAuditService;
  githubAuthority(): GitHubGoogleAuthoritySource;
  captureEmployeeAuthority(): Promise<EmployeeEntitlementAuthority>;
  names(
    lease: ResourceLeaseRepository,
    capture: () => Promise<GoogleDirectoryUser[]>,
    history?: WorkspaceLedgerHistoryIndex,
  ): WorkspaceNameServices;
  trycomp(): TrycompPeopleSyncRuntime;
  sentry(lease?: ResourceLeaseRepository): SentryWorkspaceExecutionPort;
  pagerDuty(lease?: ResourceLeaseRepository): PagerDutyTeamExecutionPort;
  googleCleanup(
    lease?: ResourceLeaseRepository,
  ): GoogleGroupCleanupServiceContract;
  readonly githubPolicy: WorkspaceGitHubPolicy;
  readonly pagerDutyPolicy: PagerDutyTeamSyncSettings;
}
