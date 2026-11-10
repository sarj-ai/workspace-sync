import { DatabaseSync } from "node:sqlite";

import { describe, expect, it } from "vitest";

import { LEDGER_HISTORY_SQL } from "../src/workspace-directory/ledger-history-sql.ts";

const SCOPE = ["TEXAMPLE", "CLEDGER", "BEXAMPLE"] as const;

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE slack_ledger_history (
      ledger TEXT, team_id TEXT, channel_id TEXT, bot_id TEXT, revision INTEGER,
      synced_through_ts TEXT, scan_newest_ts TEXT, scan_before_ts TEXT,
      PRIMARY KEY(ledger, team_id, channel_id, bot_id)
    );
    CREATE TABLE slack_ledger_message (
      ledger TEXT, team_id TEXT, channel_id TEXT, bot_id TEXT, change_key TEXT, message_ts TEXT,
      PRIMARY KEY(ledger, team_id, channel_id, bot_id, change_key, message_ts)
    );`);
  return db;
}

describe("shared ledger SQL", () => {
  it.each(["workspace-directory", "access-guard"] as const)(
    "stores pages only at the current revision: %s",
    (ledger) => {
      const db = database();
      try {
        const sql = LEDGER_HISTORY_SQL[ledger];
        db.prepare(sql.start).run(...SCOPE);
        db.prepare(sql.insertPage).run(
          ...SCOPE,
          JSON.stringify([{ changeKey: "first", timestamp: "1.000000" }]),
          0,
        );
        expect(
          db.prepare(sql.advance).run(...SCOPE, "1.000000", null, null, 0)
            .changes,
        ).toBe(1);
        db.prepare(sql.insertPage).run(
          ...SCOPE,
          JSON.stringify([{ changeKey: "stale", timestamp: "2.000000" }]),
          0,
        );
        expect(
          db.prepare(sql.advance).run(...SCOPE, "2.000000", null, null, 0)
            .changes,
        ).toBe(0);
        expect(db.prepare(sql.find).get(...SCOPE, "first")).toMatchObject({
          timestamp: "1.000000",
        });
        expect(db.prepare(sql.find).get(...SCOPE, "stale")).toBeUndefined();
        expect(db.prepare(sql.checkpoint).get(...SCOPE)).toMatchObject({
          revision: 1,
          syncedThrough: "1.000000",
        });
      } finally {
        db.close();
      }
    },
  );

  it("isolates ledgers and tenant scopes while detecting duplicate change keys", () => {
    const db = database();
    try {
      const workspace = LEDGER_HISTORY_SQL["workspace-directory"];
      const access = LEDGER_HISTORY_SQL["access-guard"];
      db.prepare(workspace.record).run(...SCOPE, "change", "1.000000");
      expect(db.prepare(workspace.find).get(...SCOPE, "change")).toMatchObject({
        timestamp: "1.000000",
      });
      expect(db.prepare(access.find).get(...SCOPE, "change")).toBeUndefined();
      db.prepare(access.record).run(...SCOPE, "change", "9.000000");
      expect(db.prepare(access.find).get(...SCOPE, "change")).toMatchObject({
        timestamp: "9.000000",
      });
      expect(db.prepare(workspace.find).get(...SCOPE, "change")).toMatchObject({
        timestamp: "1.000000",
      });
      expect(
        db.prepare(workspace.find).get("TOTHER", SCOPE[1], SCOPE[2], "change"),
      ).toBeUndefined();
      expect(db.prepare(workspace.duplicate).get(...SCOPE)).toBeUndefined();
      db.prepare(workspace.record).run(...SCOPE, "change", "2.000000");
      expect(db.prepare(workspace.duplicate).get(...SCOPE)).toMatchObject({
        "change_key": "change",
      });
    } finally {
      db.close();
    }
  });
});
