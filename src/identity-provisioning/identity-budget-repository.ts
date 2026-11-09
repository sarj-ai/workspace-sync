import type { D1Database } from "@cloudflare/workers-types";

import type {
  IdentityBudgetParentKey,
  IdentityBudgetReservation,
  IdentityBudgetServiceId,
} from "./identity-budget-contracts.ts";
import {
  IdentityBudgetReservationSchema,
  IdentityBudgetReserveInputSchema,
} from "./identity-budget-contracts.ts";

interface BudgetKey {
  readonly parentExecutionKey: IdentityBudgetParentKey;
  readonly serviceId: IdentityBudgetServiceId;
}
type ReserveInput = BudgetKey & { readonly googleUserIds: readonly string[] };
const READ = `SELECT parent_execution_key AS parentExecutionKey, service_id AS serviceId,
  google_user_id AS googleUserId, reserved_at_ms AS reservedAtMs
  FROM identity_reconciliation_budget_reservation WHERE parent_execution_key = ?1 AND service_id = ?2`;

interface IdentityBudgetReservationReader {
  read(input: BudgetKey): Promise<IdentityBudgetReservation | null>;
}
interface IdentityBudgetReservationWriter {
  reserve(input: ReserveInput): Promise<{
    readonly kind: "matched" | "reserved";
    readonly reservation: IdentityBudgetReservation;
  }>;
}

export class IdentityBudgetRepository
  implements IdentityBudgetReservationReader, IdentityBudgetReservationWriter
{
  readonly #db: D1Database;
  readonly #now: () => number;

  constructor(db: D1Database, now: () => number = Date.now) {
    this.#db = db;
    this.#now = now;
  }

  async reserve(input: ReserveInput): Promise<{
    readonly kind: "matched" | "reserved";
    readonly reservation: IdentityBudgetReservation;
  }> {
    const parsed = IdentityBudgetReserveInputSchema.parse(input);
    const identities = [...new Set(parsed.googleUserIds)];
    if (identities.length !== 1)
      throw new Error("identity_budget_multiple_identities");
    const reservation = IdentityBudgetReservationSchema.parse({
      parentExecutionKey: parsed.parentExecutionKey,
      serviceId: parsed.serviceId,
      googleUserId: identities[0],
      reservedAtMs: this.#now(),
    });
    const session = this.#db.withSession("first-primary");
    const [inserted, selected] = await session.batch([
      session
        .prepare(`INSERT INTO identity_reconciliation_budget_reservation
        (parent_execution_key, service_id, google_user_id, reserved_at_ms)
        SELECT ?1, ?2, ?3, ?4 WHERE NOT EXISTS (
          SELECT 1 FROM identity_reconciliation_budget_reservation WHERE parent_execution_key = ?1 AND service_id = ?2
        )`)
        .bind(
          reservation.parentExecutionKey,
          reservation.serviceId,
          reservation.googleUserId,
          reservation.reservedAtMs,
        ),
      session
        .prepare(READ)
        .bind(reservation.parentExecutionKey, reservation.serviceId),
    ]);
    const stored = IdentityBudgetReservationSchema.parse(selected?.results[0]);
    if (stored.googleUserId !== reservation.googleUserId)
      throw new Error("identity_budget_exhausted");
    return {
      kind: inserted?.meta.changes === 1 ? "reserved" : "matched",
      reservation: stored,
    };
  }

  async read(input: BudgetKey): Promise<IdentityBudgetReservation | null> {
    const key = IdentityBudgetReserveInputSchema.pick({
      parentExecutionKey: true,
      serviceId: true,
    }).parse(input);
    const row = await this.#db
      .withSession("first-primary")
      .prepare(READ)
      .bind(key.parentExecutionKey, key.serviceId)
      .first();
    return row === null ? null : IdentityBudgetReservationSchema.parse(row);
  }
}
