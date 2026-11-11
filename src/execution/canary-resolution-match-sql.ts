export const CANARY_RESOLUTION_MATCH_SQL = `EXISTS (
  SELECT 1 FROM workspace_branch_attempt_resolution AS resolution
  JOIN workspace_reviewed_slack_lifecycle_intent AS intent ON intent.intent_id = resolution.intent_id
  JOIN identity_reconciliation_budget_reservation AS budget
    ON budget.parent_execution_key = resolution.budget_key AND budget.service_id = 'slack'
  WHERE resolution.tick_id = workspace_directory_schedule_tick.tick_id
    AND resolution.tick_id = ?1 AND resolution.source_hash = ?2
    AND resolution.kind = 'not-dispatched'
    AND resolution.evidence_id = ?3
    AND resolution.snapshot_json = workspace_directory_schedule_tick.snapshot_json
    AND resolution.tick_revision = workspace_directory_schedule_tick.revision
    AND workspace_directory_schedule_tick.scheduled_at_ms = json_extract(resolution.snapshot_json, '$.scheduledAtMs')
    AND workspace_directory_schedule_tick.worker_version_id = json_extract(resolution.snapshot_json, '$.deployment.id')
    AND workspace_directory_schedule_tick.worker_revision = json_extract(resolution.snapshot_json, '$.deployment.revision')
    AND intent.state = 'claimed' AND intent.claimed_tick_id = resolution.tick_id
    AND intent.proof_json = resolution.proof_json AND intent.claimed_at_ms = resolution.claimed_at_ms
    AND intent.expires_at_ms = json_extract(resolution.proof_json, '$.expiresAtMs')
    AND budget.google_user_id = json_extract(resolution.proof_json, '$.reviewed.googleUserId')
    AND budget.reserved_at_ms > intent.expires_at_ms
    AND budget.parent_execution_key = 'identity-budget:v1:scheduled:organization-sync:' || workspace_directory_schedule_tick.scheduled_at_ms
    AND json_extract(resolution.triggers_json, '$.identity_reconciliation_budget_no_update') =
      (SELECT sql FROM sqlite_schema WHERE name = 'identity_reconciliation_budget_no_update' AND type = 'trigger')
    AND json_extract(resolution.triggers_json, '$.identity_reconciliation_budget_no_delete') =
      (SELECT sql FROM sqlite_schema WHERE name = 'identity_reconciliation_budget_no_delete' AND type = 'trigger')
    AND json_extract(resolution.triggers_json, '$.identity_reconciliation_budget_no_replace') =
      (SELECT sql FROM sqlite_schema WHERE name = 'identity_reconciliation_budget_no_replace' AND type = 'trigger')
    AND json_extract(resolution.triggers_json, '$.workspace_branch_resolution_no_update') =
      (SELECT sql FROM sqlite_schema WHERE name = 'workspace_branch_resolution_no_update' AND type = 'trigger')
    AND json_extract(resolution.triggers_json, '$.workspace_branch_resolution_no_delete') =
      (SELECT sql FROM sqlite_schema WHERE name = 'workspace_branch_resolution_no_delete' AND type = 'trigger')
    AND json_extract(resolution.triggers_json, '$.workspace_branch_resolution_no_replace') =
      (SELECT sql FROM sqlite_schema WHERE name = 'workspace_branch_resolution_no_replace' AND type = 'trigger')
)`;
