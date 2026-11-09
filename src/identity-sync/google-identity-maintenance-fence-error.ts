/** Server-owned proof that scheduler admission stays fenced during a single identity mutation. */
export interface GoogleIdentityMaintenanceWriteGuard {
  assertWriteAuthority(planExpiresAtMs?: number): Promise<void>;
  beforeDispatch?(): Promise<void>;
  readonly deadlineAtMs: number;
}
export interface GoogleIdentityAttestationGuard<
  ReviewedPlan,
> extends GoogleIdentityMaintenanceWriteGuard {
  beginAttempt(plan: ReviewedPlan): Promise<string>;
  resolveAttempt(attemptId: string, wire: unknown): Promise<void>;
  settleObservedAttempt(
    attemptId: string,
    wire: unknown,
    kind: "observed-after" | "observed-before",
    changeHash: string,
  ): Promise<void>;
}
export interface GoogleIdentityMaintenanceFence<ReviewedPlan> {
  withFence<Result>(
    operation: (
      guard: GoogleIdentityAttestationGuard<ReviewedPlan>,
    ) => Promise<Result>,
  ): Promise<Result>;
}
export class GoogleIdentityMaintenanceFenceError extends Error {
  constructor(options?: ErrorOptions) {
    super("google_identity_maintenance_fence_required", options);
    this.name = "GoogleIdentityMaintenanceFenceError";
  }
}
