import { DatabaseSync, type SQLInputValue } from "node:sqlite";

import { describe, expect, it } from "vitest";

import { VERIFIED_LIFECYCLE_COHORT_SQL } from "../src/identity-provisioning/verified-lifecycle-cohort-sql.ts";

const HASH = "a".repeat(64);
const INPUT = [
  "source",
  "owner",
  1,
  "user",
  "deleted",
  HASH,
  "delete",
  2000,
  "deleted",
  HASH,
  5000,
] satisfies SQLInputValue[];

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(`-- dialect: sqlite
  CREATE TABLE identity_lifecycle_event (
    event_key TEXT PRIMARY KEY, google_user_id TEXT NOT NULL,
    authority_state TEXT NOT NULL, payload_hash TEXT NOT NULL,
    event_kind TEXT NOT NULL, occurred_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL, claim_owner_id TEXT, claim_generation INTEGER DEFAULT 0,
    claim_expires_at_ms INTEGER, completed_at_ms INTEGER, error_code TEXT,
    next_attempt_at_ms INTEGER, completion_source_event_key TEXT,
    completion_authority_state TEXT, completion_authority_payload_hash TEXT
  );
  CREATE INDEX idx_identity_lifecycle_retry_schedule
    ON identity_lifecycle_event(state, next_attempt_at_ms);
  CREATE INDEX idx_identity_lifecycle_pending_equivalent
    ON identity_lifecycle_event(google_user_id, authority_state, payload_hash,
      event_kind, occurred_at_ms DESC, event_key) WHERE state = 'pending';`);
  db.prepare(`INSERT INTO identity_lifecycle_event
    (event_key,google_user_id,authority_state,payload_hash,event_kind,
      occurred_at_ms,state,claim_owner_id,claim_generation,claim_expires_at_ms)
    VALUES ('source','user','deleted',?,'delete',1000,'claimed','owner',1,8000)`).run(
    HASH,
  );
  return db;
}

function pending(
  db: DatabaseSync,
  key: string,
  occurredAtMs = 900,
  user = "user",
) {
  db.prepare(`INSERT INTO identity_lifecycle_event
    (event_key,google_user_id,authority_state,payload_hash,event_kind,
      occurred_at_ms,state,error_code,next_attempt_at_ms)
    VALUES (?,?,'deleted',?,'delete',?,'pending','transient',10000)`).run(
    key,
    user,
    HASH,
    occurredAtMs,
  );
}

describe("verified lifecycle cohort SQL", () => {
  it("probes the matching pending index after the single verified claim", () => {
    const db = database();
    try {
      pending(db, "matching");
      const details = db
        .prepare(`EXPLAIN QUERY PLAN ${VERIFIED_LIFECYCLE_COHORT_SQL}`)
        .all(...INPUT)
        .map((row) => String(row.detail));
      expect(details).toContain(
        "SEARCH pending USING COVERING INDEX idx_identity_lifecycle_pending_equivalent (google_user_id=? AND authority_state=? AND payload_hash=? AND event_kind=? AND occurred_at_ms<?)",
      );
      expect(
        db.prepare(VERIFIED_LIFECYCLE_COHORT_SQL).run(...INPUT).changes,
      ).toBe(2);
    } finally {
      db.close();
    }
  });

  it("completes only the verified source and matching older events with full receipts", () => {
    const db = database();
    try {
      pending(db, "older");
      pending(db, "same-time", 1000);
      pending(db, "newer", 1001);
      pending(db, "other-user", 900, "another-user");
      pending(db, "other-payload");
      pending(db, "other-kind");
      pending(db, "other-authority");
      db.prepare(
        "UPDATE identity_lifecycle_event SET payload_hash=? WHERE event_key='other-payload'",
      ).run("b".repeat(64));
      db.exec(
        "UPDATE identity_lifecycle_event SET event_kind='update' WHERE event_key='other-kind'",
      );
      db.exec(
        "UPDATE identity_lifecycle_event SET authority_state='active' WHERE event_key='other-authority'",
      );
      expect(
        db.prepare(VERIFIED_LIFECYCLE_COHORT_SQL).run(...INPUT).changes,
      ).toBe(3);
      const completed = db
        .prepare(`SELECT event_key, completed_at_ms,
        error_code, next_attempt_at_ms, claim_owner_id, claim_expires_at_ms,
        completion_source_event_key, completion_authority_state,
        completion_authority_payload_hash
        FROM identity_lifecycle_event WHERE state='completed' ORDER BY event_key`)
        .all();
      expect(completed).toEqual(
        ["older", "same-time", "source"].map((key) => ({
          "event_key": key,
          "completed_at_ms": 2000,
          "error_code": null,
          "next_attempt_at_ms": null,
          "claim_owner_id": null,
          "claim_expires_at_ms": null,
          "completion_source_event_key": "source",
          "completion_authority_state": "deleted",
          "completion_authority_payload_hash": HASH,
        })),
      );
      expect(
        db
          .prepare(
            "SELECT event_key FROM identity_lifecycle_event WHERE state='pending' ORDER BY event_key",
          )
          .all(),
      ).toEqual(
        [
          "newer",
          "other-authority",
          "other-kind",
          "other-payload",
          "other-user",
        ].map((key) => ({ "event_key": key })),
      );
    } finally {
      db.close();
    }
  });

  it.each([
    ["missing source", 0, "absent"],
    ["wrong owner", 1, "stale-owner"],
    ["stale generation", 2, 2],
    ["wrong subject", 3, "another-user"],
    ["wrong authority", 4, "active"],
    ["wrong payload", 5, "b".repeat(64)],
    ["wrong kind", 6, "update"],
  ] satisfies [string, number, SQLInputValue][])(
    "leaves every row unchanged for %s",
    (_name, index, value) => {
      const db = database();
      try {
        pending(db, "older");
        const args: SQLInputValue[] = [...INPUT];
        args[index] = value;
        const before = db
          .prepare("SELECT * FROM identity_lifecycle_event ORDER BY event_key")
          .all();
        expect(
          db.prepare(VERIFIED_LIFECYCLE_COHORT_SQL).run(...args).changes,
        ).toBe(0);
        expect(
          db
            .prepare(
              "SELECT * FROM identity_lifecycle_event ORDER BY event_key",
            )
            .all(),
        ).toEqual(before);
      } finally {
        db.close();
      }
    },
  );

  it("retains source-only completion after expiry without completing pending peers", () => {
    const db = database();
    try {
      pending(db, "older");
      const args: SQLInputValue[] = [...INPUT];
      args[7] = 8000;
      expect(
        db.prepare(VERIFIED_LIFECYCLE_COHORT_SQL).run(...args).changes,
      ).toBe(1);
      expect(
        db
          .prepare(
            "SELECT state FROM identity_lifecycle_event WHERE event_key='source'",
          )
          .get(),
      ).toEqual({ state: "completed" });
      expect(
        db
          .prepare(
            "SELECT state, next_attempt_at_ms FROM identity_lifecycle_event WHERE event_key='older'",
          )
          .get(),
      ).toEqual({ state: "pending", "next_attempt_at_ms": 10000 });
    } finally {
      db.close();
    }
  });

  it("retains the 5000-event bound and deterministic key ordering at equal times", () => {
    const db = database();
    try {
      db.exec("BEGIN");
      for (let index = 0; index < 5002; index += 1)
        pending(db, `older-${String(index).padStart(4, "0")}`);
      db.exec("COMMIT");
      expect(
        db.prepare(VERIFIED_LIFECYCLE_COHORT_SQL).run(...INPUT).changes,
      ).toBe(5001);
      expect(
        db
          .prepare(
            "SELECT event_key FROM identity_lifecycle_event WHERE state='pending' ORDER BY event_key",
          )
          .all(),
      ).toEqual([{ "event_key": "older-5000" }, { "event_key": "older-5001" }]);
    } finally {
      db.close();
    }
  });
});
