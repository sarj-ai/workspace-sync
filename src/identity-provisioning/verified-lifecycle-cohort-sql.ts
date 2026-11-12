// Keep the unique verified claim outermost so cohort reads probe the pending index.
// A pending-first plan rescans pending events for every completion.
export const VERIFIED_LIFECYCLE_COHORT_SQL = `WITH verified_claim AS MATERIALIZED (
  SELECT event_key, google_user_id, authority_state, payload_hash, event_kind,
    occurred_at_ms, claim_expires_at_ms
  FROM identity_lifecycle_event
  WHERE event_key = ?1 AND state = 'claimed'
    AND claim_owner_id = ?2 AND claim_generation = ?3
    AND google_user_id = ?4 AND authority_state = ?5
    AND payload_hash = ?6 AND event_kind = ?7
), equivalent_events AS MATERIALIZED (
  SELECT pending.event_key
  FROM verified_claim AS verified
  CROSS JOIN identity_lifecycle_event AS pending
  WHERE pending.state = 'pending'
    AND pending.google_user_id = verified.google_user_id
    AND pending.authority_state = verified.authority_state
    AND pending.payload_hash = verified.payload_hash
    AND pending.event_kind = verified.event_kind
    AND pending.occurred_at_ms <= verified.occurred_at_ms
    AND pending.occurred_at_ms <= ?8 AND verified.claim_expires_at_ms > ?8
  ORDER BY pending.occurred_at_ms DESC, pending.event_key LIMIT ?11
)
UPDATE identity_lifecycle_event
SET state = 'completed', completed_at_ms = ?8, error_code = NULL,
  next_attempt_at_ms = NULL, claim_owner_id = NULL, claim_expires_at_ms = NULL,
  completion_source_event_key = ?1, completion_authority_state = ?9,
  completion_authority_payload_hash = ?10
WHERE event_key IN (SELECT event_key FROM verified_claim)
  OR event_key IN (SELECT event_key FROM equivalent_events)`;
