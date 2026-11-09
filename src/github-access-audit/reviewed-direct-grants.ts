import { dequal } from "dequal";

import { getWorkspaceSyncPolicy } from "../configuration.ts";

export interface ReviewedGitHubDirectGrantRetention {
  readonly allowedTeamSlugs: readonly string[];
  readonly githubLogin: string;
  readonly githubUserId: string;
  readonly googleUserId: string;
  readonly grants: readonly {
    readonly customRoleName?: string | undefined;
    readonly permission: "admin" | "maintain" | "pull" | "push" | "triage";
    readonly repositoryId: number;
    readonly repositoryName: string;
  }[];
  readonly primaryEmail: string;
  readonly reviewedAt: string;
}

export function matchesReviewedGitHubDirectGrants(
  reviewed: ReviewedGitHubDirectGrantRetention,
  subject: {
    readonly githubLogin: string;
    readonly githubUserId: string;
    readonly googleUserId: string;
    readonly primaryEmail: string;
  },
  grants: readonly {
    readonly customRoleName?: string | undefined;
    readonly unresolvedDirectRole?: true | undefined;
    readonly permission: string;
    readonly repositoryId: number;
    readonly repositoryName: string;
  }[],
): boolean {
  const normalize = (items: typeof grants) =>
    items
      .map(({ customRoleName, permission, repositoryId, repositoryName }) => ({
        ...(customRoleName !== undefined && { customRoleName }),
        permission,
        repositoryId,
        repositoryName,
      }))
      .toSorted((left, right) => left.repositoryId - right.repositoryId);
  return (
    reviewed.googleUserId === subject.googleUserId &&
    reviewed.githubUserId === subject.githubUserId &&
    reviewed.githubLogin.toLowerCase() === subject.githubLogin.toLowerCase() &&
    reviewed.primaryEmail === subject.primaryEmail &&
    reviewed.grants.length > 0 &&
    grants.every((grant) => grant.unresolvedDirectRole !== true) &&
    dequal(normalize(reviewed.grants), normalize(grants))
  );
}

export function reviewedGitHubDirectGrantRetentions() {
  return getWorkspaceSyncPolicy().reviewedGitHubDirectGrantRetentions;
}
