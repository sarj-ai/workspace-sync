import { getWorkspaceSyncPolicy } from "../configuration.ts";
export interface ReviewedGitHubTeamMembership {
  readonly githubLogin: string;
  readonly githubUserId: string;
  readonly googleUserId: string;
  readonly reviewedAt: string;
  readonly teamId: number;
  readonly teamSlug: string;
}

// Administrator decision on 2026-11-04: retain these existing memberships.
// These records authorize preservation only; they cannot create or restore access.

export function isReviewedGitHubTeamMembership(
  observed: Omit<ReviewedGitHubTeamMembership, "reviewedAt">,
  reviewed: readonly ReviewedGitHubTeamMembership[],
): boolean {
  return reviewed.some(
    (entry) =>
      entry.googleUserId === observed.googleUserId &&
      entry.githubUserId === observed.githubUserId &&
      entry.githubLogin.toLowerCase() === observed.githubLogin.toLowerCase() &&
      entry.teamId === observed.teamId &&
      entry.teamSlug === observed.teamSlug,
  );
}

export function reviewedGitHubTeamMemberships() {
  return getWorkspaceSyncPolicy().reviewedGitHubTeamMemberships;
}
