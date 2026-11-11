import type { z } from "zod";

/** Validated host configuration; credentials are supplied by the deployment. */
export interface WorkspaceRuntimeConfiguration {
  readonly accessGuardSlackUserToken:
    | ""
    | (string & z.core.$brand<"SlackUserToken">);
  readonly ashbyApiKey: string;
  readonly attioAccessAuditToken: string;
  readonly githubAccessAuditDisabled: boolean;
  readonly githubAccessAuditOrganization: string;
  readonly githubAccessAuditToken: string;
  readonly githubIdentityDeprovisionDisabled: boolean;
  readonly githubIdentityDeprovisionOrganizationId: string;
  readonly githubIdentityDeprovisionToken: string;
  readonly githubOrganizationSyncDisabled: boolean;
  readonly githubOrganizationSyncMaxChanges: number;
  readonly githubOrganizationSyncOrganizationId: string;
  readonly githubOrganizationSyncOrganizationLogin: string;
  readonly githubOrganizationSyncToken: string;
  readonly googleDirectoryLifecycleDisabled: boolean;
  readonly linearApiKey: string;
  readonly operationPlanSigningKey: string;
  readonly orgChannelSyncDisabled: boolean;
  readonly orgChannelSyncMode: "audit" | "live";
  readonly orgSyncDisabled: boolean;
  readonly orgSyncGoogleServiceAccountEmail: string;
  readonly orgSyncGoogleServiceAccountPrivateKey: string;
  readonly orgSyncMode: "audit" | "live";
  readonly pagerdutyApiToken: string;
  readonly pagerdutyTeamSyncDisabled: boolean;
  readonly reminderSlackBotToken: string & z.core.$brand<"SlackBotToken">;
  readonly slackBotToken: string & z.core.$brand<"SlackBotToken">;
  readonly trycompApiKey: string;
  readonly trycompSyncAllowDeactivations: boolean;
  readonly trycompSyncDisabled: boolean;
  readonly trycompSyncMode: "audit" | "live";
  readonly workspaceDirectoryGithubIdentitySeedEnabled: boolean;
  readonly workspaceDirectoryGithubIdentitySeedMaxChanges: number;
  readonly workspaceDirectoryGoogleGroupCleanupDisabled: boolean;
  readonly workspaceDirectoryGoogleGroupCleanupMode: "audit" | "live";
  readonly workspaceDirectoryLinearSuspensionsEnabled: boolean;
  readonly workspaceDirectoryParentEnabled: boolean;
  readonly workspaceDirectorySentryAuthorityPins: string;
  readonly workspaceDirectorySentryEnabled: boolean;
  readonly workspaceDirectorySentryToken: string;
  readonly workspaceDirectoryTrycompEnabled: boolean;
}
