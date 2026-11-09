import { isActiveGoogleUser } from "../google-workspace/user-lifecycle.ts";
import type { IdentityProvisioningExecutionPolicy } from "../identity-provisioning/contracts.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { logEvent } from "../shared/log-event.ts";
import type { GoogleDirectoryFullReconciliationStore } from "./d1-google-directory-full-reconciliation-store.ts";

const FULL_RECONCILIATION_DEADLINE_MS = 45_000;
const FULL_RECONCILIATION_POLICY: IdentityProvisioningExecutionPolicy = {
  kind: "audit-only",
};

export interface GoogleDirectoryFullReconciliationClient {
  listAllUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
  listDeletedUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
}

export interface GoogleDirectoryAuthorityRefreshPort {
  reconcileUser(
    user: GoogleDirectoryUser,
    eventKey: string,
    observedAt: string,
    kind: "add" | "delete" | "undelete" | "update",
    policyOverride?: IdentityProvisioningExecutionPolicy,
  ): Promise<void>;
  recoverPending?(): Promise<void>;
}

interface CompletedGoogleDirectoryReconciliation {
  readonly active: number;
  readonly deleted: number;
  readonly kind: "reconciled";
}

export type GoogleDirectoryFullReconciliationResult =
  | { readonly kind: "disabled" }
  | CompletedGoogleDirectoryReconciliation;

export interface GoogleDirectoryFullReconciliationPort {
  reconcile(
    scheduledAtMs: number,
  ): Promise<GoogleDirectoryFullReconciliationResult>;
}

export class GoogleDirectoryFullReconciler implements GoogleDirectoryFullReconciliationPort {
  readonly #client: GoogleDirectoryFullReconciliationClient;
  readonly #clock: () => number;
  readonly #enabled: boolean;
  readonly #refresh: GoogleDirectoryAuthorityRefreshPort;
  readonly #store: GoogleDirectoryFullReconciliationStore | undefined;

  constructor(
    client: GoogleDirectoryFullReconciliationClient,
    refresh: GoogleDirectoryAuthorityRefreshPort,
    enabled: boolean,
    clock: () => number = Date.now,
    store?: GoogleDirectoryFullReconciliationStore,
  ) {
    this.#client = client;
    this.#refresh = refresh;
    this.#enabled = enabled;
    this.#clock = clock;
    this.#store = store;
  }

  async reconcile(
    scheduledAtMs: number,
  ): Promise<GoogleDirectoryFullReconciliationResult> {
    if (!this.#enabled) return { kind: "disabled" };
    const runId = crypto.randomUUID();
    await this.#store?.begin(runId, scheduledAtMs, this.#clock());
    try {
      const result = await this.#reconcile(runId, scheduledAtMs);
      if (
        this.#store !== undefined &&
        !(await this.#store.complete(runId, this.#clock()))
      ) {
        throw new Error(
          "google_directory_full_reconciliation_events_incomplete",
        );
      }
      logEvent("google_directory.full_reconciliation_completed", {
        active: result.active,
        deleted: result.deleted,
        runId,
        evidenceRecorded: this.#store !== undefined,
      });
      return result;
    } catch (error) {
      await this.#store?.fail(runId, this.#clock());
      throw error;
    }
  }

  async #reconcile(
    runId: string,
    scheduledAtMs: number,
  ): Promise<CompletedGoogleDirectoryReconciliation> {
    const deadlineAt = this.#clock() + FULL_RECONCILIATION_DEADLINE_MS;
    const [active, deleted] = await Promise.all([
      this.#client.listAllUsers(runId, deadlineAt),
      this.#client.listDeletedUsers(runId, deadlineAt),
    ]);
    const activeIds = new Set(active.map(({ id }) => id));
    const overlap = deleted.find(({ id }) => activeIds.has(id));
    if (overlap !== undefined) {
      throw new Error(
        `google_directory_full_reconciliation_identity_overlap:${overlap.id}`,
      );
    }
    const users = [...active, ...deleted].toSorted((left, right) =>
      left.id.localeCompare(right.id),
    );
    if (users.length === 0)
      throw new Error("google_directory_full_reconciliation_empty_inventory");
    if (new Set(users.map(({ id }) => id)).size !== users.length) {
      throw new Error(
        "google_directory_full_reconciliation_duplicate_identity",
      );
    }
    await this.#store?.captureInventory(runId, scheduledAtMs, users);
    const observedAt = new Date(scheduledAtMs).toISOString();
    const failures: unknown[] = [];
    try {
      await this.#refresh.recoverPending?.();
    } catch (error) {
      failures.push(error);
    }
    for (const user of users) {
      try {
        // eslint-disable-next-line no-await-in-loop -- Each inactive person gets a separately bounded recovery; failures must not starve later subjects.
        await this.#refresh.reconcileUser(
          user,
          `google-directory:full:${String(scheduledAtMs)}:${user.id}`,
          observedAt,
          user.deletionTime === undefined ? "update" : "delete",
          isActiveGoogleUser(user) ? FULL_RECONCILIATION_POLICY : undefined,
        );
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length > 0)
      throw new AggregateError(
        failures,
        "google_directory_full_reconciliation_incomplete",
      );
    return {
      active: active.length,
      deleted: deleted.length,
      kind: "reconciled",
    };
  }
}
