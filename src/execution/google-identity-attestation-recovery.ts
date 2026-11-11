import type { D1Database } from "@cloudflare/workers-types";

import {
  classifyIdentityAttempt,
  GitHubIdentityAttestationAttemptStore,
  observeIdentityAttempt,
} from "../identity-sync/github-identity-attestation-attempt-store.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { GoogleWorkspaceIdentityUserGateway } from "../org-sync/google-identity-schema.ts";
import { GoogleIdentityAttestationMaintenanceFence } from "./google-identity-attestation-maintenance-fence.ts";

/** Reads one immutable historical target only. Recovery has no provider mutation port. */
interface IdentityAttemptRecoverySnapshot {
  attemptId: null | string;
  resolved: boolean;
  sourceHash: string;
  target: "after" | "before" | null;
}
interface SettleIdentityAttemptInput {
  attemptId: string;
  changeHash: string;
  sourceHash: string;
  target: "after" | "before";
}
export interface IGoogleIdentityAttestationRecovery {
  read(): Promise<IdentityAttemptRecoverySnapshot>;
  settle(input: SettleIdentityAttemptInput): Promise<void>;
}
export class GoogleIdentityAttestationRecovery implements IGoogleIdentityAttestationRecovery {
  readonly #database: D1Database;
  readonly #store: GitHubIdentityAttestationAttemptStore;
  readonly #google: Pick<GoogleWorkspaceIdentityUserGateway, "readUserById">;
  readonly #now: () => number;
  constructor(
    database: D1Database,
    google: Pick<GoogleWorkspaceIdentityUserGateway, "readUserById">,
    now: () => number = Date.now,
  ) {
    this.#database = database;
    this.#store = new GitHubIdentityAttestationAttemptStore(database, now);
    this.#google = google;
    this.#now = now;
  }
  async read(): Promise<IdentityAttemptRecoverySnapshot> {
    const attempt = await this.#store.latest();
    if (attempt === null)
      return {
        attemptId: null,
        sourceHash: await sha256Hex({
          kind: "google-identity-attempt-recovery/empty",
        }),
        resolved: true,
        target: null,
      };
    if (
      attempt.resolution === null &&
      this.#now() < attempt.snapshot.recoverAfterMs
    )
      throw conflict();
    const entry = attempt.snapshot.plan.entries[0];
    if (entry === undefined) throw conflict();
    const observation =
      attempt.resolution?.observation ??
      observeIdentityAttempt(
        attempt,
        await this.#google.readUserById(
          entry.googlePlan.user.id,
          this.#now() + 60_000,
        ),
      );
    const target = classifyIdentityAttempt(attempt, observation);
    if (target === "drifted") throw conflict();
    return {
      attemptId: attempt.attemptId,
      sourceHash: await sha256Hex(
        JsonValueSchema.parse({
          attemptId: attempt.attemptId,
          snapshot: attempt.snapshot,
          observation,
        }),
      ),
      resolved: attempt.resolution !== null,
      target,
    };
  }
  async settle(input: SettleIdentityAttemptInput): Promise<void> {
    const fence = new GoogleIdentityAttestationMaintenanceFence(
      this.#database,
      this.#now,
      input.attemptId,
    );
    await fence.withFence(async (guard) => {
      const snapshot = await this.read();
      if (
        snapshot.attemptId !== input.attemptId ||
        snapshot.sourceHash !== input.sourceHash ||
        snapshot.resolved ||
        snapshot.target !== input.target
      )
        throw conflict();
      const attempt = await this.#store.read(input.attemptId);
      const entry = attempt.snapshot.plan.entries[0];
      if (entry === undefined) throw conflict();
      const wire = await this.#google.readUserById(
        entry.googlePlan.user.id,
        guard.deadlineAtMs,
      );
      const observed = observeIdentityAttempt(attempt, wire);
      if (classifyIdentityAttempt(attempt, observed) !== input.target)
        throw conflict();
      await guard.settleObservedAttempt(
        input.attemptId,
        wire,
        input.target === "before" ? "observed-before" : "observed-after",
        input.changeHash,
      );
    });
  }
}
function conflict() {
  return new Error("google_identity_attempt_recovery_conflict");
}
