import { z } from "zod";

import {
  type AuthorityIdentity,
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { GoogleDirectoryAuthorityReader } from "../identity-lifecycle/google-directory-authority-reader.ts";
import {
  assertRetainedGoogleGitHubOwnership,
  D1GoogleDirectoryIdentityHistory,
} from "../identity-lifecycle/google-directory-identity-history.ts";
import { projectGoogleDirectoryAuthority } from "../identity-lifecycle/project-google-directory-authority.ts";
import type {
  IdentityProviderConnector,
  IdentityProviderObserver,
  IdentityProvisioningExecutionPolicy,
  ProviderObservation,
} from "../identity-provisioning/contracts.ts";
import { DesiredIdentityStatePlanner } from "../identity-provisioning/desired-identity-state-planner.ts";
import { buildEmployeeEntitlementAuthority } from "../identity-provisioning/employee-entitlement-policy.ts";
import { GitHubAuditOnlyConnector } from "../identity-provisioning/git-hub-audit-only-connector.ts";
import { GitHubManagedDeprovisionConnector } from "../identity-provisioning/github-managed-deprovision-connector.ts";
import { IdentityProvisioningOrchestrator } from "../identity-provisioning/orchestrator.ts";
import { D1IdentityProvisioningRepository } from "../identity-provisioning/persistence.ts";
import { DIRECTORY_READONLY_SCOPE } from "../org-sync/google-directory-client.ts";
import { GoogleGroupsClient } from "../org-sync/google-groups-client.ts";
import { normalizeGooglePrivateKey } from "../org-sync/normalize-google-private-key.ts";
import type { WorkspaceSyncRuntimeBindings } from "./provider-runtime-ports.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";

const GitHubUserSchema = z.object({
  id: z.number().int().positive(),
  login: z.string().min(1),
});
class GitHubOrganizationMembershipObserver implements IdentityProviderObserver {
  readonly #fetchImpl: typeof fetch;
  readonly #organization: string;
  readonly #token: string;
  constructor(
    organization: string,
    token: string,
    fetchImpl: typeof fetch = runtimeFetch,
  ) {
    this.#organization = organization;
    this.#token = token;
    this.#fetchImpl = fetchImpl;
  }
  async observe(subject: AuthorityIdentity): Promise<ProviderObservation> {
    if (subject.github.kind !== "verified") {
      return {
        detail: "Google authority has no verified GitHub identity to observe",
        kind: "unsupported",
        providerId: "github",
      };
    }
    const account = await this.#getUser(subject.github.githubLogin);
    if (
      account.login.toLocaleLowerCase("en-US") !== subject.github.githubLogin ||
      String(account.id) !== subject.github.githubUserId
    ) {
      return {
        candidates: [
          {
            githubLogin: GitHubLoginSchema.parse(account.login),
            githubUserId: GitHubUserIdSchema.parse(String(account.id)),
            providerId: "github",
          },
        ],
        kind: "ambiguous",
        providerId: "github",
      };
    }
    const membership = await this.#fetchImpl(
      `https://api.github.com/orgs/${encodeURIComponent(this.#organization)}/members/${encodeURIComponent(subject.github.githubLogin)}`,
      { headers: this.#headers() },
    );
    await membership.body?.cancel();
    if (membership.status === 404)
      return { kind: "absent", providerId: "github" };
    if (membership.status !== 204) {
      throw new Error(
        `GitHub organization membership HTTP ${String(membership.status)}`,
      );
    }
    return {
      account: {
        githubLogin: subject.github.githubLogin,
        githubUserId: subject.github.githubUserId,
        providerId: "github",
      },
      kind: "present",
      providerId: "github",
    };
  }
  async #getUser(
    login: z.output<typeof GitHubLoginSchema>,
  ): Promise<z.output<typeof GitHubUserSchema>> {
    const response = await this.#fetchImpl(
      `https://api.github.com/users/${encodeURIComponent(login)}`,
      { headers: this.#headers() },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `GitHub user observation HTTP ${String(response.status)}`,
      );
    }
    return GitHubUserSchema.parse(await response.json());
  }
  #headers(): HeadersInit {
    return {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${this.#token}`,
      "user-agent": "sarj-identity-audit",
      "x-github-api-version": "2022-11-28",
    };
  }
}
export function createIdentityProvisioningOrchestrator(
  bindings: WorkspaceSyncRuntimeBindings,
  env: ValidatedEnv,
  db: D1Database,
): IdentityProvisioningOrchestrator {
  const organization = env.githubAccessAuditOrganization;
  const token = env.githubAccessAuditToken;
  const managed = !env.githubIdentityDeprovisionDisabled;
  if (
    managed &&
    (organization === "" ||
      env.githubIdentityDeprovisionOrganizationId === "" ||
      env.githubIdentityDeprovisionToken === "")
  ) {
    throw new Error("github_identity_deprovision_configuration_incomplete");
  }
  const connectors: IdentityProviderConnector[] = [];
  if (managed) {
    const history = new D1GoogleDirectoryIdentityHistory(db);
    const directory = bindings.google(
      "github_deprovision_prewrite",
      DIRECTORY_READONLY_SCOPE,
    );
    const authority = new GoogleDirectoryAuthorityReader(directory);
    connectors.push(
      new GitHubManagedDeprovisionConnector({
        readGoogleAuthority: async (googleUserId) => {
          const observed = await authority.getUserById(
            googleUserId,
            crypto.randomUUID(),
          );
          const user =
            observed === null ? null : await history.restoreDeleted(observed);
          if (
            user?.deletionTime !== undefined &&
            user.customSchemas?.SarjIdentity !== undefined
          ) {
            const active = await directory.listAllUsers(crypto.randomUUID());
            if (
              active.length <
                getWorkspaceSyncPolicy().org.minimumGoogleParticipants ||
              getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds.some(
                (id) =>
                  !active.some(
                    (other) =>
                      other.id === id &&
                      other.suspended !== true &&
                      other.archived !== true &&
                      other.deletionTime === undefined,
                  ),
              )
            )
              throw new Error("github_deprovision_google_authority_incomplete");
            assertRetainedGoogleGitHubOwnership(user, active);
          }
          return user === null
            ? null
            : projectGoogleDirectoryAuthority(user, new Date().toISOString());
        },
        organizationId: env.githubIdentityDeprovisionOrganizationId,
        organizationLogin: organization,
        planner: new DesiredIdentityStatePlanner(),
        token: env.githubIdentityDeprovisionToken,
      }),
    );
  } else if (
    !env.githubAccessAuditDisabled &&
    organization !== "" &&
    token !== ""
  ) {
    connectors.push(
      new GitHubAuditOnlyConnector(
        new GitHubOrganizationMembershipObserver(organization, token),
        new DesiredIdentityStatePlanner(),
      ),
    );
  }
  return new IdentityProvisioningOrchestrator({
    captureEmployeeEntitlementAuthority: () =>
      bindings.captureEmployeeAuthority(),
    claimDurationMs: 60000,
    claimOwnerId: () => crypto.randomUUID(),
    clock: () => Date.now(),
    connectors,
    repository: new D1IdentityProvisioningRepository(db),
    runId: () => crypto.randomUUID(),
  });
}
export function createEmployeeEntitlementAuthorityCapture(env: ValidatedEnv) {
  const groups = new GoogleGroupsClient({
    adminSubject: getWorkspaceSyncPolicy().org.googleAdminSubject,
    operation: "employee_entitlement_authority",
    privateKey: normalizeGooglePrivateKey(
      env.orgSyncGoogleServiceAccountPrivateKey,
    ),
    serviceAccountEmail: env.orgSyncGoogleServiceAccountEmail,
    userProject: getWorkspaceSyncPolicy().org.googleUserProject,
  });
  return async () => {
    const snapshots = await groups.listGroups(
      [getWorkspaceSyncPolicy().contractorAuthorityGroup.email],
      crypto.randomUUID(),
      Date.now() + 60000,
    );
    const snapshot = snapshots[0];
    if (snapshot === undefined || snapshots.length !== 1) {
      throw new Error("contractor_authority_snapshot_missing");
    }
    return buildEmployeeEntitlementAuthority(snapshot);
  };
}
export function identityLifecycleProvisioningPolicy(
  env: ValidatedEnv,
): IdentityProvisioningExecutionPolicy {
  if (!env.githubIdentityDeprovisionDisabled) {
    return {
      kind: "bounded-automatic-deprovision",
    };
  }
  return {
    kind: "kill-switch-engaged",
    reason: "github_identity_deprovision_disabled",
  };
}
