import type { D1Database } from "@cloudflare/workers-types";

import type { GitHubIdentityAdminAttestationPlan } from "../identity-sync/github-identity-admin-attestation.ts";
import { GitHubIdentityAttestationAttemptStore } from "../identity-sync/github-identity-attestation-attempt-store.ts";
import {
  type GoogleIdentityAttestationGuard,
  type GoogleIdentityMaintenanceFence,
  GoogleIdentityMaintenanceFenceError,
} from "../identity-sync/google-identity-maintenance-fence-error.ts";
import { D1ResourceLeaseRepository } from "../identity-sync/resource-lease.ts";
import { D1WorkspaceDeploymentFenceRepository } from "../workspace-directory/workspace-deployment-fence-repository.ts";
import { WorkspaceScheduleHealthRepository } from "./workspace-schedule-health-repository.ts";

const LEASE_DURATION_MS = 600_000;
const MINIMUM_WRITE_REMAINING_MS = 90_000;
const READBACK_EXPIRY_MARGIN_MS = 30_000;

/** Acquires the same atomic fence checked by scheduler admission; never pauses or rewrites an existing tick. */
export class GoogleIdentityAttestationMaintenanceFence implements GoogleIdentityMaintenanceFence<GitHubIdentityAdminAttestationPlan> {
  readonly #admission: D1WorkspaceDeploymentFenceRepository;
  readonly #leases: D1ResourceLeaseRepository;
  readonly #health: WorkspaceScheduleHealthRepository;
  readonly #now: () => number;
  readonly #attempts: GitHubIdentityAttestationAttemptStore;
  readonly #database: D1Database;
  readonly #permittedAttemptId: string | undefined;
  constructor(
    database: D1Database,
    now: () => number = Date.now,
    permittedAttemptId?: string,
  ) {
    this.#database = database;
    this.#permittedAttemptId = permittedAttemptId;
    this.#attempts = new GitHubIdentityAttestationAttemptStore(database, now);
    this.#now = now;
    this.#admission = new D1WorkspaceDeploymentFenceRepository(database, {
      clock: now,
    });
    this.#leases = new D1ResourceLeaseRepository(database, { clock: now });
    this.#health = new WorkspaceScheduleHealthRepository(database, now);
  }
  async withFence<Result>(
    operation: (
      guard: GoogleIdentityAttestationGuard<GitHubIdentityAdminAttestationPlan>,
    ) => Promise<Result>,
  ): Promise<Result> {
    const acquisition = await this.#admission.acquire(LEASE_DURATION_MS);
    if (acquisition.kind !== "acquired")
      throw new GoogleIdentityMaintenanceFenceError();
    const { lease } = acquisition;
    try {
      const health = await this.#health.health({
        nowMs: this.#now(),
        maxAgeMs: LEASE_DURATION_MS,
      });
      if (health.pendingTicks !== 0 || !(await this.#allowedDebt(health)))
        throw new GoogleIdentityMaintenanceFenceError();
      const guard: GoogleIdentityAttestationGuard<GitHubIdentityAdminAttestationPlan> =
        {
          deadlineAtMs: lease.expiresAtMs - READBACK_EXPIRY_MARGIN_MS,
          beginAttempt: (plan) =>
            this.#attempts.begin(
              plan,
              lease,
              lease.expiresAtMs - READBACK_EXPIRY_MARGIN_MS,
            ),
          resolveAttempt: (attemptId, wire) =>
            this.#attempts.resolve({
              attemptId,
              lease,
              wire,
              kind: "write-verified",
            }),
          settleObservedAttempt: (attemptId, wire, kind, changeHash) =>
            this.#attempts.resolve({
              attemptId,
              lease,
              wire,
              kind,
              changeHash,
            }),
          assertWriteAuthority: async (planExpiresAtMs) => {
            try {
              await this.#leases.assertActive(
                lease,
                MINIMUM_WRITE_REMAINING_MS,
              );
              if (
                planExpiresAtMs !== undefined &&
                this.#now() >= planExpiresAtMs
              )
                throw new GoogleIdentityMaintenanceFenceError();
            } catch (cause) {
              throw new GoogleIdentityMaintenanceFenceError({ cause });
            }
          },
        };
      await guard.assertWriteAuthority();
      return await operation(guard);
    } finally {
      await this.#admission.release(lease);
    }
  }
  async #allowedDebt(health: {
    mutationSafetyClear: boolean;
    unresolvedMutations: number;
  }): Promise<boolean> {
    if (this.#permittedAttemptId === undefined)
      return health.mutationSafetyClear;
    if (health.unresolvedMutations !== 1) return false;
    const found = await this.#database
      .prepare(`SELECT 1 AS allowed FROM google_identity_attestation
      WHERE kind IS NULL AND attempt_id=?1 AND EXISTS (SELECT 1 FROM trycomp_sync_breaker WHERE breaker_key='org-sync/trycomp-people' AND state='closed')`)
      .bind(this.#permittedAttemptId)
      .first("allowed");
    return found === 1;
  }
}
