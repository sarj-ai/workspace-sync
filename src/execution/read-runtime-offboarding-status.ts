import { LinearAccessProvider } from "../access-guard/linear-provider.ts";
import { DownstreamAccountSchema } from "../access-guard/model.ts";
import { SlackAccessClient } from "../access-guard/slack-access-client.ts";
import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { D1GoogleDirectoryIdentityHistory } from "../identity-lifecycle/google-directory-identity-history.ts";
import { mergeGoogleDirectoryAuthority } from "../org-sync/google-directory-authority.ts";
import {
  DIRECTORY_READONLY_SCOPE,
  GoogleDirectoryClient,
} from "../org-sync/google-directory-client.ts";
import { normalizeGooglePrivateKey } from "../org-sync/normalize-google-private-key.ts";
import { TrycompPeopleClient } from "../trycomp/client.ts";
import { SentryWorkspaceClient } from "../workspace-directory/sentry-workspace-client.ts";
import { createWorkspaceAccessAuditProviders } from "./create-workspace-access-audit-providers.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import {
  type OffboardingReader,
  readOffboardingStatus,
} from "./offboarding-status.ts";
import { readAshbyOffboardingAccounts } from "./read-ashby-offboarding-accounts.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";
import {
  assertSentryWorkspaceAuthorityPins,
  sentryWorkspaceAuthorityPinState,
} from "./sentry-workspace-authority-pins.ts";
import { trycompOffboardingAccounts } from "./trycomp-offboarding-accounts.ts";
export function readRuntimeOffboardingStatus(
  env: ValidatedEnv,
  subject: string,
  db?: D1Database,
) {
  const runId = crypto.randomUUID();
  const readers: OffboardingReader[] = [
    {
      provider: "github",
      capability: "automatic",
      automationEnabled:
        !env.githubIdentityDeprovisionDisabled &&
        !env.googleDirectoryLifecycleDisabled,
      minimumAccounts:
        getWorkspaceExecutionPolicy().accessGuard.minimumProviderAccounts
          .github,
      read: () =>
        createWorkspaceAccessAuditProviders(env).github.readAccess(runId),
    },
    {
      provider: "linear",
      capability: "automatic",
      automationEnabled:
        env.workspaceDirectoryParentEnabled &&
        env.workspaceDirectoryLinearSuspensionsEnabled &&
        !env.orgSyncDisabled &&
        env.orgSyncMode === "live",
      minimumAccounts:
        getWorkspaceExecutionPolicy().accessGuard.minimumProviderAccounts
          .linear,
      read: () =>
        new LinearAccessProvider(env.linearApiKey, {
          expectedOrganizationId:
            getWorkspaceExecutionPolicy().accessGuard
              .expectedLinearOrganizationId,
          expectedOrganizationUrlKey:
            getWorkspaceExecutionPolicy().accessGuard
              .expectedLinearOrganizationUrlKey,
        }).listAccounts(runId),
    },
    {
      provider: "slack",
      capability: "manual",
      minimumAccounts:
        getWorkspaceExecutionPolicy().accessGuard.minimumProviderAccounts.slack,
      read: () =>
        new SlackAccessClient({
          botToken: env.slackBotToken,
          channelId: getWorkspaceExecutionPolicy().accessGuard.alertsChannelId,
          expectedTeamId: getWorkspaceSyncPolicy().org.expectedSlackTeamId,
          userToken: env.accessGuardSlackUserToken,
        }).listAccounts(runId),
    },
    {
      provider: "attio",
      capability: "manual",
      minimumAccounts:
        getWorkspaceExecutionPolicy().accessGuard.minimumProviderAccounts.attio,
      read: () =>
        createWorkspaceAccessAuditProviders(env).attio.listAccounts(runId),
    },
    {
      provider: "pagerduty",
      capability: "manual",
      minimumAccounts:
        getWorkspaceExecutionPolicy().accessGuard.minimumProviderAccounts
          .pagerduty,
      read: () =>
        createWorkspaceAccessAuditProviders(env).pagerDuty.listAccounts(runId),
    },
    {
      provider: "ashby",
      capability: "manual",
      minimumAccounts: 1,
      read: () =>
        readAshbyOffboardingAccounts({
          apiKey: env.ashbyApiKey,
          expectedRootEmail: getWorkspaceSyncPolicy().org.googleAdminSubject,
        }),
    },
    {
      provider: "sentry",
      capability: "automatic",
      automationEnabled:
        env.workspaceDirectoryParentEnabled &&
        env.workspaceDirectorySentryEnabled &&
        !env.orgSyncDisabled &&
        env.orgSyncMode === "live",
      minimumAccounts: 1,
      read: () => readSentry(env),
    },
    {
      provider: "trycomp",
      capability: "automatic",
      automationEnabled:
        !env.trycompSyncDisabled &&
        env.trycompSyncAllowDeactivations &&
        env.trycompSyncMode === "live" &&
        (!env.workspaceDirectoryParentEnabled ||
          env.workspaceDirectoryTrycompEnabled),
      minimumAccounts: 1,
      read: async () => {
        if (!env.trycompApiKey)
          throw new Error("offboarding_credentials_missing");
        const members = await new TrycompPeopleClient(
          env.trycompApiKey,
        ).listMembers(runId);
        return trycompOffboardingAccounts(members);
      },
    },
  ];
  return readOffboardingStatus({
    googleUsers: async () => {
      const google = new GoogleDirectoryClient({
        adminSubject: getWorkspaceSyncPolicy().org.googleAdminSubject,
        privateKey: normalizeGooglePrivateKey(
          env.orgSyncGoogleServiceAccountPrivateKey,
        ),
        scope: DIRECTORY_READONLY_SCOPE,
        serviceAccountEmail: env.orgSyncGoogleServiceAccountEmail,
        userProject: getWorkspaceSyncPolicy().org.googleUserProject,
      });
      const [active, deleted] = await Promise.all([
        google.listAllUsers(runId),
        google.listDeletedUsers(runId),
      ]);
      const history =
        db === undefined ? undefined : new D1GoogleDirectoryIdentityHistory(db);
      const retained =
        history === undefined
          ? deleted
          : await Promise.all(
              deleted.map((user) => history.restoreDeleted(user)),
            );
      return mergeGoogleDirectoryAuthority(active, retained);
    },
    minimumGoogleUsers: getWorkspaceSyncPolicy().org.minimumGoogleParticipants,
    readers,
    rootGoogleUserIds: getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds,
    subject,
  });
}
async function readSentry(env: ValidatedEnv) {
  const pins = sentryWorkspaceAuthorityPinState(
    env.workspaceDirectorySentryAuthorityPins,
  );
  if (!env.workspaceDirectorySentryToken || pins.kind !== "ready")
    throw new Error("offboarding_sentry_authority_unavailable");
  const client = new SentryWorkspaceClient({
    organizationSlug: getWorkspaceExecutionPolicy().sentry.organizationSlug,
    projectSlug: "platform",
    teamSlug: "platform",
    token: env.workspaceDirectorySentryToken,
  });
  assertSentryWorkspaceAuthorityPins(
    pins.pins,
    await client.authorityBootstrap(),
  );
  const members = await client.listOrganizationMembers();
  return members.map((member) =>
    DownstreamAccountSchema.parse({
      active: true,
      email: member.email ?? member.user?.email,
      id: member.id,
    }),
  );
}
