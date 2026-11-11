import { CANARY_RESOLUTION_MATCH_SQL } from "./canary-resolution-match-sql.ts";

// Keep the verified membership view in one expansion on D1's affected runtime.
export const RESOLVED_BRANCH_ATTEMPT_CTES_SQL = `resolved_branch_attempt AS MATERIALIZED (
  SELECT tick_id FROM workspace_verified_branch_attempt_resolution
  UNION ALL
  SELECT tick_id FROM workspace_directory_schedule_tick
  WHERE tick_id = ?1 AND ${CANARY_RESOLUTION_MATCH_SQL}
)`;

export const RESOLVED_BRANCH_ATTEMPT_MATCH_SQL = `EXISTS (
  SELECT 1 FROM resolved_branch_attempt AS resolution
  WHERE resolution.tick_id = workspace_directory_schedule_tick.tick_id
)`;
