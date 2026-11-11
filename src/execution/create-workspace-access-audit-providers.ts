import {
  AttioAccessProvider,
  GitHubOrganizationAccessProvider,
  PagerDutyAccessProvider,
} from "../access-guard/workspace-providers.ts";
import {
  getWorkspaceExecutionPolicy,
  type WorkspaceRuntimePolicy,
} from "./get-workspace-execution-policy.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";
type AccessAuditProviderEnv = Pick<
  ValidatedEnv,
  | "attioAccessAuditToken"
  | "githubAccessAuditOrganization"
  | "githubAccessAuditToken"
  | "pagerdutyApiToken"
>;

type AccessAuditTenantSettings = Pick<
  WorkspaceRuntimePolicy,
  "expectedAttioWorkspaceId" | "expectedGitHubOrganization"
>;

export function createWorkspaceAccessAuditProviders(
  env: AccessAuditProviderEnv,
  settings: AccessAuditTenantSettings = getWorkspaceExecutionPolicy()
    .accessGuard,
) {
  const configuredOrganization = env.githubAccessAuditOrganization.trim();
  if (
    configuredOrganization &&
    configuredOrganization !== settings.expectedGitHubOrganization
  ) {
    throw new Error("access_guard_github_organization_mismatch");
  }
  return {
    attio: new AttioAccessProvider(
      env.attioAccessAuditToken,
      settings.expectedAttioWorkspaceId,
    ),
    github: new GitHubOrganizationAccessProvider(
      env.githubAccessAuditToken,
      settings.expectedGitHubOrganization,
    ),
    pagerDuty: new PagerDutyAccessProvider(env.pagerdutyApiToken),
  } as const;
}
