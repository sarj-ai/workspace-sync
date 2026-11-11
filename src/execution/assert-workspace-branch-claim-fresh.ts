interface Approval {
  planGeneratedAt: string;
  reviewedProviderIntent?: { proof: { expiresAtMs: number } } | undefined;
  reviewedSlackLifecycleIntent?: { proof: { expiresAtMs: number } } | undefined;
}

export function assertWorkspaceBranchClaimFresh(
  params: Approval,
  now: number,
): void {
  const generatedAt = Date.parse(params.planGeneratedAt);
  const expiresAt = Math.min(
    generatedAt + 600_000,
    params.reviewedProviderIntent?.proof.expiresAtMs ?? Infinity,
    params.reviewedSlackLifecycleIntent?.proof.expiresAtMs ?? Infinity,
  );
  if (
    !Number.isSafeInteger(now) ||
    !Number.isFinite(generatedAt) ||
    now < generatedAt ||
    now >= expiresAt
  )
    throw new Error("workspace_branch_plan_expired");
}
