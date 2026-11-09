export const LEDGER_HISTORY_SQL = {
  "workspace-directory": {
    start: `INSERT INTO workspace_directory_ledger_history
        (team_id, channel_id, bot_id, revision)
        VALUES (?1, ?2, ?3, 0) ON CONFLICT DO NOTHING`,
    insertPage: `INSERT INTO workspace_directory_ledger_message
            (team_id, channel_id, bot_id, change_key, message_ts)
            SELECT ?1, ?2, ?3, json_extract(value, '$.changeKey'), json_extract(value, '$.timestamp')
            FROM json_each(?4)
            WHERE EXISTS (SELECT 1 FROM workspace_directory_ledger_history
              WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3 AND revision = ?5)
            ON CONFLICT DO NOTHING`,
    advance: `UPDATE workspace_directory_ledger_history
            SET revision = revision + 1, synced_through_ts = ?4,
              scan_newest_ts = ?5, scan_before_ts = ?6
            WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3 AND revision = ?7`,
    find: `SELECT message_ts AS timestamp FROM workspace_directory_ledger_message
        WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3 AND change_key = ?4
        LIMIT 2`,
    record: `INSERT INTO workspace_directory_ledger_message
        (team_id, channel_id, bot_id, change_key, message_ts)
        VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING`,
    checkpoint: `SELECT revision, synced_through_ts AS syncedThrough,
          scan_newest_ts AS scanNewest, scan_before_ts AS scanBefore
        FROM workspace_directory_ledger_history
        WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3`,
    duplicate: `SELECT change_key FROM workspace_directory_ledger_message
        WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3
        GROUP BY change_key HAVING COUNT(*) > 1 LIMIT 1`,
  },
  "access-guard": {
    start: `INSERT INTO access_guard_ledger_history
        (team_id, channel_id, bot_id, revision)
        VALUES (?1, ?2, ?3, 0) ON CONFLICT DO NOTHING`,
    insertPage: `INSERT INTO access_guard_ledger_message
            (team_id, channel_id, bot_id, change_key, message_ts)
            SELECT ?1, ?2, ?3, json_extract(value, '$.changeKey'), json_extract(value, '$.timestamp')
            FROM json_each(?4)
            WHERE EXISTS (SELECT 1 FROM access_guard_ledger_history
              WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3 AND revision = ?5)
            ON CONFLICT DO NOTHING`,
    advance: `UPDATE access_guard_ledger_history
            SET revision = revision + 1, synced_through_ts = ?4,
              scan_newest_ts = ?5, scan_before_ts = ?6
            WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3 AND revision = ?7`,
    find: `SELECT message_ts AS timestamp FROM access_guard_ledger_message
        WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3 AND change_key = ?4
        LIMIT 2`,
    record: `INSERT INTO access_guard_ledger_message
        (team_id, channel_id, bot_id, change_key, message_ts)
        VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING`,
    checkpoint: `SELECT revision, synced_through_ts AS syncedThrough,
          scan_newest_ts AS scanNewest, scan_before_ts AS scanBefore
        FROM access_guard_ledger_history
        WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3`,
    duplicate: `SELECT change_key FROM access_guard_ledger_message
        WHERE team_id = ?1 AND channel_id = ?2 AND bot_id = ?3
        GROUP BY change_key HAVING COUNT(*) > 1 LIMIT 1`,
  },
} as const;
