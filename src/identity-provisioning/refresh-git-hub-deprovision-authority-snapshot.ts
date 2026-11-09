import type { GitHubDeprovisionAuthority } from "../github-access-audit/github-deprovision-authority-contract.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  type GitHubDeprovisionAuthoritySnapshotStorePort,
} from "./github-deprovision-authority-snapshot-store.ts";

export interface GitHubDeprovisionAuthorityRefreshPorts {
  captureGitHub(): Promise<GitHubDeprovisionAuthority>;
  captureGoogle(): Promise<{
    readonly deletedUsers: readonly GoogleDirectoryUser[];
    readonly users: readonly GoogleDirectoryUser[];
  }>;
  now?: () => Date;
  store: GitHubDeprovisionAuthoritySnapshotStorePort;
}

export interface GitHubDeprovisionAuthorityRefreshResult {
  readonly capturedAt: string;
  readonly deletedUsers: number;
  readonly githubMembers: number;
  readonly githubRepositories: number;
  readonly users: number;
}

/* Refreshes the one atomic cache value and preserves the previous value on partial capture. */
export async function refreshGitHubDeprovisionAuthoritySnapshot(
  ports: GitHubDeprovisionAuthorityRefreshPorts,
): Promise<GitHubDeprovisionAuthorityRefreshResult> {
  const capturedAt = (ports.now ?? (() => new Date()))().toISOString();
  const github = await ports.captureGitHub();
  if (github.errors.length > 0 || github.organization === null) {
    throw new Error("github_deprovision_authority_capture_incomplete");
  }
  // Observe the sole lifecycle authority only after the target-side inventory is complete.
  const google = await ports.captureGoogle();
  await ports.store.write({
    capturedAt,
    github,
    google: {
      complete: true,
      deletedUsers: google.deletedUsers,
      users: google.users,
    },
    schemaVersion: GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  });
  return {
    capturedAt,
    deletedUsers: google.deletedUsers.length,
    githubMembers: github.members.length,
    githubRepositories: github.repositories.length,
    users: google.users.length,
  };
}
