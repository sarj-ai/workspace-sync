import type { IdentityProvisioningExecutionPolicy } from "../identity-provisioning/contracts.ts";
import type { IdentityProvisioningReconciler } from "../identity-provisioning/orchestrator.ts";
import type {
  IdentityLifecycleEventClaim,
  IdentityLifecycleEventStore,
  IdentityProvisioningClaim,
} from "../identity-provisioning/persistence.ts";
import {
  IdentityLifecycleEventInputSchema,
  IdentityTombstoneInputSchema,
} from "../identity-provisioning/persistence.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { logEvent } from "../shared/log-event.ts";
import { authorityPayloadHash } from "./authority-payload-hash.ts";
import {
  type AuthoritativeGoogleDirectoryUserState,
  authoritativeGoogleDirectoryUserState,
  type RefreshGoogleDirectoryUserTask,
} from "./contracts.ts";
import {
  GoogleDirectoryAuthorityReader,
  type GoogleDirectoryAuthoritySourcePort,
} from "./google-directory-authority-reader.ts";
import type { IGoogleDirectoryIdentityHistory } from "./google-directory-identity-history.ts";
import { projectGoogleDirectoryAuthority } from "./project-google-directory-authority.ts";

const REFRESH_DEADLINE_MS = 30_000;
const CLAIM_DURATION_MS = 60_000;
const TOMBSTONE_RETENTION_MS = 90 * 24 * 60 * 60 * 1_000;
const MAX_RECOVERY_EVENTS = 25;

export type GoogleDirectoryLifecycleRefreshClient =
  GoogleDirectoryAuthoritySourcePort;

export type GoogleDirectoryLifecycleRefreshStore = Pick<
  IdentityLifecycleEventStore,
  | "claimLifecycleEvent"
  | "claimNextLifecycleEvent"
  | "clearTombstone"
  | "completeLifecycleEvent"
  | "completeVerifiedLifecycleCohort"
  | "holdExpiredDeletedAuthority"
  | "recordLifecycleEvent"
  | "recordTombstone"
  | "retryLifecycleEvent"
>;

export interface GoogleDirectoryLifecycleRefreshPort {
  handle(task: RefreshGoogleDirectoryUserTask): Promise<void>;
  reconcileUser(
    user: GoogleDirectoryUser,
    eventKey: string,
    observedAt: string,
    kind: "add" | "delete" | "undelete" | "update",
    policyOverride?: IdentityProvisioningExecutionPolicy,
  ): Promise<void>;
  recoverPending(): Promise<void>;
}

function eventKind(event: RefreshGoogleDirectoryUserTask["event"]) {
  return event === "makeAdmin" ? ("update" as const) : event;
}

async function authoritativeUser(
  client: GoogleDirectoryLifecycleRefreshClient,
  task: RefreshGoogleDirectoryUserTask,
  nowMs: number,
): Promise<GoogleDirectoryUser> {
  const runId = crypto.randomUUID();
  const deadlineAt = nowMs + REFRESH_DEADLINE_MS;
  const authoritative = await new GoogleDirectoryAuthorityReader(
    client,
  ).getUserById(task.googleUserId, runId, deadlineAt);
  if (authoritative !== null) return authoritative;
  if (task.event !== "delete")
    throw new Error("google_directory_authoritative_user_missing");
  return {
    deletionTime: task.observedAt,
    id: task.googleUserId,
    primaryEmail: task.notificationPrimaryEmail,
  };
}

function acquiredClaim(
  claim: IdentityProvisioningClaim<IdentityLifecycleEventClaim>,
): IdentityLifecycleEventClaim | null {
  return claim.kind === "acquired" ? claim.claim : null;
}

export class GoogleDirectoryLifecycleRefreshHandler implements GoogleDirectoryLifecycleRefreshPort {
  readonly #client: GoogleDirectoryLifecycleRefreshClient;
  readonly #clock: () => number;
  readonly #enabled: boolean;
  readonly #provisioning: IdentityProvisioningReconciler | undefined;
  readonly #provisioningPolicy: IdentityProvisioningExecutionPolicy;
  readonly #store: GoogleDirectoryLifecycleRefreshStore;
  readonly #identityHistory: IGoogleDirectoryIdentityHistory | undefined;

  constructor(dependencies: {
    client: GoogleDirectoryLifecycleRefreshClient;
    clock?: () => number;
    enabled?: boolean;
    provisioning?: IdentityProvisioningReconciler;
    provisioningPolicy?: IdentityProvisioningExecutionPolicy;
    store: GoogleDirectoryLifecycleRefreshStore;
    identityHistory?: IGoogleDirectoryIdentityHistory;
  }) {
    this.#client = dependencies.client;
    this.#clock = dependencies.clock ?? Date.now;
    this.#enabled = dependencies.enabled ?? true;
    this.#provisioning = dependencies.provisioning;
    this.#provisioningPolicy = dependencies.provisioningPolicy ?? {
      kind: "audit-only",
    };
    this.#store = dependencies.store;
    this.#identityHistory = dependencies.identityHistory;
  }

  async handle(task: RefreshGoogleDirectoryUserTask): Promise<void> {
    if (!this.#enabled) {
      logEvent("google_directory.lifecycle_refresh_skip", {
        reason: "disabled",
      });
      return;
    }
    const nowMs = this.#clock();
    const user = await authoritativeUser(this.#client, task, nowMs);
    await this.reconcileUser(
      user,
      task.notificationId,
      task.observedAt,
      eventKind(task.event),
    );
  }

  async reconcileUser(
    user: GoogleDirectoryUser,
    eventKey: string,
    observedAt: string,
    kind: "add" | "delete" | "undelete" | "update",
    policyOverride?: IdentityProvisioningExecutionPolicy,
  ): Promise<void> {
    if (!this.#enabled) return;
    const nowMs = this.#clock();
    const state: AuthoritativeGoogleDirectoryUserState =
      authoritativeGoogleDirectoryUserState(user);
    const payloadHash = await authorityPayloadHash(state);
    const observedAtMs = Date.parse(observedAt);
    await this.#store.recordLifecycleEvent(
      IdentityLifecycleEventInputSchema.parse({
        authorityState: state.state,
        eventKey,
        googleUserId: user.id,
        kind,
        occurredAtMs: observedAtMs,
        payloadHash,
        receivedAtMs: observedAtMs,
      }),
    );
    const claim = acquiredClaim(
      await this.#store.claimLifecycleEvent(
        eventKey,
        crypto.randomUUID(),
        nowMs,
        CLAIM_DURATION_MS,
      ),
    );
    if (claim === null) return;

    await this.#reconcileClaim(user, observedAt, kind, claim, policyOverride);
  }

  async recoverPending(): Promise<void> {
    if (!this.#enabled) return;
    const failures: unknown[] = [];
    const failedClaims: IdentityLifecycleEventClaim[] = [];
    const deadlineAt = this.#clock() + REFRESH_DEADLINE_MS;
    for (
      let index = 0;
      index < MAX_RECOVERY_EVENTS && this.#clock() < deadlineAt;
      index += 1
    ) {
      // eslint-disable-next-line no-await-in-loop -- Each atomic claim advances the durable cursor.
      const result = await this.#store.claimNextLifecycleEvent(
        crypto.randomUUID(),
        this.#clock(),
        CLAIM_DURATION_MS * 5,
      );
      if (result.kind !== "acquired") break;
      const claim = result.claim;
      try {
        // eslint-disable-next-line no-await-in-loop -- Recovery observes current authority instead of replaying a stale suspended snapshot.
        const user = await new GoogleDirectoryAuthorityReader(
          this.#client,
        ).getUserById(claim.googleUserId, crypto.randomUUID(), deadlineAt);
        if (user === null) {
          // eslint-disable-next-line no-await-in-loop -- Hold only the exact expired deletion cohort after fresh authoritative absence.
          await this.#holdMissingAuthority(claim);
          continue;
        }
        // eslint-disable-next-line no-await-in-loop -- Keep provider concurrency bounded to one subject.
        await this.#reconcileClaim(
          user,
          new Date(this.#clock()).toISOString(),
          claim.kind,
          claim,
          undefined,
          true,
        );
      } catch (error) {
        // Keep failed claims leased until the pass ends so one blocked event cannot starve the others.
        failedClaims.push(claim);
        failures.push(error);
      }
    }
    for (const claim of failedClaims) {
      try {
        // eslint-disable-next-line no-await-in-loop -- Release each exact fenced claim after the bounded pass.
        await this.#store.retryLifecycleEvent(
          claim,
          "lifecycle_recovery_incomplete",
          this.#clock(),
        );
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length > 0)
      throw new AggregateError(
        failures,
        "google_directory_lifecycle_recovery_incomplete",
      );
  }

  async #holdMissingAuthority(
    claim: IdentityLifecycleEventClaim,
  ): Promise<void> {
    const heldEvents = await this.#store.holdExpiredDeletedAuthority(
      claim,
      this.#clock(),
    );
    if (heldEvents === 0)
      throw new Error("google_directory_recovery_authority_missing");
    logEvent("google_directory.lifecycle_manual_review_required", {
      events: heldEvents,
      reason: "deleted_authority_expired",
    });
  }

  async #reconcileClaim(
    user: GoogleDirectoryUser,
    observedAt: string,
    kind: "add" | "delete" | "undelete" | "update",
    claim: IdentityLifecycleEventClaim,
    policyOverride?: IdentityProvisioningExecutionPolicy,
    recoveringHistoricalClaim = false,
  ): Promise<void> {
    const state = authoritativeGoogleDirectoryUserState(user);
    const eventKey = claim.eventKey;

    try {
      // Tombstones record Google authority independently of downstream completion.
      // Historical claims retain their original authority state; fresh snapshot events own tombstone transitions.
      if (
        !recoveringHistoricalClaim &&
        state.state === "deleted" &&
        kind === "delete"
      ) {
        const deletedAtMs = Date.parse(state.deletedAt);
        await this.#store.recordTombstone(
          IdentityTombstoneInputSchema.parse({
            deletedAtMs,
            googleUserId: state.googleUserId,
            lifecycleEventKey: eventKey,
            primaryEmail: state.lastKnownPrimaryEmail ?? user.primaryEmail,
            retainedUntilMs: deletedAtMs + TOMBSTONE_RETENTION_MS,
          }),
          claim,
        );
      } else if (!recoveringHistoricalClaim && state.state !== "deleted") {
        // A fresh active Directory record is authoritative anti-entropy even when the
        // undelete notification was missed. Full reconciliation intentionally emits
        // `update`, so limiting cleanup to an explicit `undelete` leaves a stale
        // deletion tombstone behind forever.
        await this.#store.clearTombstone(user.id, eventKey, claim);
      }
      const providerEvidence = await this.#reconcileProvisioning(
        user,
        observedAt,
        policyOverride,
      );
      await this.#completeReconciledClaim(claim, state, providerEvidence);
    } catch (error) {
      if (recoveringHistoricalClaim) throw error;
      try {
        await this.#store.retryLifecycleEvent(
          claim,
          "lifecycle_refresh_incomplete",
          this.#clock(),
        );
      } catch (retryError) {
        logEvent("google_directory.lifecycle_retry_record_failed", {
          error:
            retryError instanceof Error
              ? retryError.message
              : String(retryError),
          event: kind,
        });
      }
      throw error;
    }
    logEvent("google_directory.lifecycle_refreshed", {
      event: kind,
      state: state.state,
    });
  }

  async #completeReconciledClaim(
    claim: IdentityLifecycleEventClaim,
    state: AuthoritativeGoogleDirectoryUserState,
    providerEvidence: boolean,
  ): Promise<void> {
    if (
      !providerEvidence ||
      this.#store.completeVerifiedLifecycleCohort === undefined
    ) {
      await this.#store.completeLifecycleEvent(claim, this.#clock());
      return;
    }
    const events = await this.#store.completeVerifiedLifecycleCohort(
      claim,
      this.#clock(),
      {
        authorityState: state.state,
        googleUserId: state.googleUserId,
        payloadHash: await authorityPayloadHash(state),
      },
    );
    if (events > 1)
      logEvent("google_directory.lifecycle_pending_events_coalesced", {
        events,
        state: state.state,
      });
  }

  async #reconcileProvisioning(
    user: GoogleDirectoryUser,
    observedAt: string,
    policyOverride: IdentityProvisioningExecutionPolicy | undefined,
  ): Promise<boolean> {
    await this.#identityHistory?.remember(user, Date.parse(observedAt));
    if (this.#provisioning === undefined) return false;
    const authority =
      (await this.#identityHistory?.restoreDeleted(user)) ?? user;
    const inactive =
      authoritativeGoogleDirectoryUserState(user).state !== "active";
    const policy = inactive
      ? (policyOverride ?? this.#provisioningPolicy)
      : { kind: "audit-only" as const };
    const result = await this.#provisioning.reconcile(
      [projectGoogleDirectoryAuthority(authority, observedAt)],
      policy,
    );
    assertProvisioningCompleted(result, inactive);
    return result.planning.length > 0 || result.executions.length > 0;
  }
}

function assertProvisioningCompleted(
  result: Awaited<ReturnType<IdentityProvisioningReconciler["reconcile"]>>,
  requireDeprovision: boolean,
): void {
  for (const planningResult of result.planning) {
    if (planningResult.kind === "failed") {
      throw new Error(
        `identity_provisioning_planning_failed:${planningResult.providerId}:${planningResult.errorCode}`,
      );
    }
    if (requireDeprovision && planningResult.decision.kind === "blocked") {
      throw new Error(
        `identity_provisioning_planning_blocked:${planningResult.providerId}`,
      );
    }
  }
  const incompleteExecution = result.executions.find(
    ({ kind }) =>
      kind === "failed" ||
      kind === "claim-unavailable" ||
      (requireDeprovision && kind !== "succeeded"),
  );
  if (incompleteExecution === undefined) {
    if (
      requireDeprovision &&
      result.planning.length === 0 &&
      result.executions.length === 0
    )
      throw new Error("identity_provisioning_no_providers");
    return;
  }
  let errorCode: string = incompleteExecution.kind;
  if (incompleteExecution.kind === "failed")
    errorCode = incompleteExecution.errorCode;
  if (incompleteExecution.kind === "claim-unavailable")
    errorCode = "claim_unavailable";
  throw new Error(
    `identity_provisioning_execution_incomplete:${incompleteExecution.providerId}:${errorCode}`,
  );
}
