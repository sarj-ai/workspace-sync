import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import type { SlackChannelRemovalSafety } from "./channel-model.ts";
import { SlackWriteOutcomeUnknownError } from "./slack-api-transport.ts";

const SourceGoogleGroupIdsSchema = z.array(z.string().min(1)).min(1);

export interface ChannelMembershipObservation {
  afterMember: boolean;
  beforeMember: boolean;
  channelId: string;
  slackUserId: string;
}

export interface ChannelMembershipRemovalCandidate {
  channelId: string;
  slackUserId: string;
}

export interface ChannelMembershipRemovalPlan extends ChannelMembershipRemovalCandidate {
  channelName: string;
  isPrivate: boolean;
}

export interface ChannelMembershipProvenanceSource {
  slackUserGroupId: string;
  sourceGoogleGroupIds: string[];
}

export interface ChannelMembershipProvenanceRepository {
  isExclusiveReleasedCandidate(
    candidate: ChannelMembershipRemovalCandidate,
  ): Promise<boolean>;
  listExclusiveReleasedCandidates(
    limit: number,
    eligibleSlackUserIds?: readonly string[],
  ): Promise<ChannelMembershipRemovalCandidate[]>;
  listSources(
    candidate: ChannelMembershipRemovalCandidate,
  ): Promise<ChannelMembershipProvenanceSource[]>;
  markRemoved(
    candidate: ChannelMembershipRemovalCandidate,
    runId: string,
  ): Promise<void>;
  recordAdditionObservations(input: {
    observations: readonly ChannelMembershipObservation[];
    runId: string;
    slackUserGroupId: string;
    sourceGoogleGroupIds: readonly string[];
  }): Promise<void>;
  releaseSource(input: {
    runId: string;
    slackUserGroupId: string;
    slackUserIds: readonly string[];
  }): Promise<void>;
}

export interface ChannelRemovalSlackPort {
  getChannelRemovalSafety(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<SlackChannelRemovalSafety>;
  kick(
    channelId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    userId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void>;
  listChannelMembers(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<string[]>;
}

export function selectProvenanceCaptureChannelIds(
  writeChannelIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Both collections contain Slack channel IDs; their qualifiers describe states of the same identity role.
  allowedChannelIds: readonly string[],
): string[] {
  const allowed = new Set(allowedChannelIds);
  return [...new Set(writeChannelIds)]
    .filter((channelId) => allowed.has(channelId))
    .toSorted((left, right) => left.localeCompare(right));
}

interface CountRow {
  count: number;
}

interface CandidateRow {
  "channel_id": string;
  "slack_user_id": string;
}

export class D1ChannelMembershipProvenanceRepository implements ChannelMembershipProvenanceRepository {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async recordAdditionObservations(input: {
    observations: readonly ChannelMembershipObservation[];
    runId: string;
    slackUserGroupId: string;
    sourceGoogleGroupIds: readonly string[];
  }): Promise<void> {
    const now = Date.now();
    const sourceIdsJson = JSON.stringify(
      [...new Set(input.sourceGoogleGroupIds)].toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      ),
    );
    for (const observation of input.observations) {
      if (!observation.afterMember) continue;
      // eslint-disable-next-line no-await-in-loop -- each observation is conditionally persisted from prior durable state.
      const existing = await this.#db
        .prepare(
          `SELECT COUNT(*) AS count FROM slack_channel_membership_provenance
           WHERE channel_id = ?1 AND slack_user_id = ?2 AND removed_at_ms IS NULL`,
        )
        .bind(observation.channelId, observation.slackUserId)
        .first<CountRow>();
      const automationCreated = !observation.beforeMember;
      if (!automationCreated && (existing?.count ?? 0) === 0) continue;
      if (automationCreated) {
        // eslint-disable-next-line no-await-in-loop -- D1 provenance writes are serialized per observed edge.
        await this.#db
          .prepare(
            `INSERT INTO slack_channel_membership_provenance
              (channel_id, slack_user_id, created_by_run_id, created_at_ms, last_verified_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(channel_id, slack_user_id) DO UPDATE SET
               last_verified_at_ms = excluded.last_verified_at_ms
             WHERE removed_at_ms IS NULL`,
          )
          .bind(
            observation.channelId,
            observation.slackUserId,
            input.runId,
            now,
          )
          .run();
      } else {
        // eslint-disable-next-line no-await-in-loop -- D1 provenance writes are serialized per observed edge.
        await this.#db
          .prepare(
            `UPDATE slack_channel_membership_provenance SET last_verified_at_ms = ?3
             WHERE channel_id = ?1 AND slack_user_id = ?2 AND removed_at_ms IS NULL`,
          )
          .bind(observation.channelId, observation.slackUserId, now)
          .run();
      }
      // eslint-disable-next-line no-await-in-loop -- source reference follows its durable membership record.
      await this.#db
        .prepare(
          `INSERT INTO slack_channel_membership_provenance_source
            (channel_id, slack_user_id, slack_user_group_id, source_google_group_ids_json,
             first_observed_at_ms, last_verified_at_ms)
           VALUES (?1, ?2, ?3, ?4, ?5, ?5)
           ON CONFLICT(channel_id, slack_user_id, slack_user_group_id) DO UPDATE SET
             last_verified_at_ms = excluded.last_verified_at_ms,
             released_by_run_id = NULL,
             released_at_ms = NULL
           WHERE source_google_group_ids_json = excluded.source_google_group_ids_json`,
        )
        .bind(
          observation.channelId,
          observation.slackUserId,
          input.slackUserGroupId,
          sourceIdsJson,
          now,
        )
        .run();
    }
  }

  async releaseSource(input: {
    runId: string;
    slackUserGroupId: string;
    slackUserIds: readonly string[];
  }): Promise<void> {
    if (input.slackUserIds.length === 0) return;
    const now = Date.now();
    for (const userId of new Set(input.slackUserIds)) {
      // eslint-disable-next-line no-await-in-loop -- each source release is independently durable.
      await this.#db
        .prepare(
          `UPDATE slack_channel_membership_provenance_source
           SET released_by_run_id = ?3, released_at_ms = ?4
           WHERE slack_user_group_id = ?1 AND slack_user_id = ?2 AND released_at_ms IS NULL`,
        )
        .bind(input.slackUserGroupId, userId, input.runId, now)
        .run();
    }
  }

  async listExclusiveReleasedCandidates(
    limit: number,
    eligibleSlackUserIds?: readonly string[],
  ): Promise<ChannelMembershipRemovalCandidate[]> {
    if (limit <= 0) return [];
    const eligibleIds = eligibleSlackUserIds
      ? [...new Set(eligibleSlackUserIds)].toSorted(
          (sortLeft, sortRight) =>
            Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
        )
      : undefined;
    if (eligibleIds?.length === 0) return [];
    const result = await this.#db
      .prepare(
        `SELECT membership.channel_id, membership.slack_user_id
         FROM slack_channel_membership_provenance membership
         WHERE membership.removed_at_ms IS NULL
           AND (?2 IS NULL OR membership.slack_user_id IN (SELECT value FROM json_each(?2)))
           AND EXISTS (
             SELECT 1 FROM slack_channel_membership_provenance_source source
             WHERE source.channel_id = membership.channel_id
               AND source.slack_user_id = membership.slack_user_id
           )
           AND NOT EXISTS (
             SELECT 1 FROM slack_channel_membership_provenance_source source
             WHERE source.channel_id = membership.channel_id
               AND source.slack_user_id = membership.slack_user_id
               AND source.released_at_ms IS NULL
           )
         ORDER BY membership.created_at_ms, membership.channel_id, membership.slack_user_id
         LIMIT ?1`,
      )
      .bind(limit, eligibleIds ? JSON.stringify(eligibleIds) : null)
      .all<CandidateRow>();
    return result.results.map((row) => ({
      channelId: row["channel_id"],
      slackUserId: row["slack_user_id"],
    }));
  }

  async isExclusiveReleasedCandidate(
    candidate: ChannelMembershipRemovalCandidate,
  ): Promise<boolean> {
    const row = await this.#db
      .prepare(
        `SELECT COUNT(*) AS count
         FROM slack_channel_membership_provenance membership
         WHERE membership.channel_id = ?1 AND membership.slack_user_id = ?2
           AND membership.removed_at_ms IS NULL
           AND EXISTS (
             SELECT 1 FROM slack_channel_membership_provenance_source source
             WHERE source.channel_id = membership.channel_id
               AND source.slack_user_id = membership.slack_user_id
           )
           AND NOT EXISTS (
             SELECT 1 FROM slack_channel_membership_provenance_source source
             WHERE source.channel_id = membership.channel_id
               AND source.slack_user_id = membership.slack_user_id
               AND source.released_at_ms IS NULL
           )`,
      )
      .bind(candidate.channelId, candidate.slackUserId)
      .first<CountRow>();
    return row?.count === 1;
  }

  async listSources(
    candidate: ChannelMembershipRemovalCandidate,
  ): Promise<ChannelMembershipProvenanceSource[]> {
    const result = await this.#db
      .prepare(
        `SELECT slack_user_group_id, source_google_group_ids_json
         FROM slack_channel_membership_provenance_source
         WHERE channel_id = ?1 AND slack_user_id = ?2
         ORDER BY slack_user_group_id`,
      )
      .bind(candidate.channelId, candidate.slackUserId)
      .all<{
        "slack_user_group_id": string;
        "source_google_group_ids_json": string;
      }>();
    return result.results.map((row) => ({
      slackUserGroupId: row["slack_user_group_id"],
      sourceGoogleGroupIds: parseSourceGoogleGroupIds(
        row["source_google_group_ids_json"],
      ),
    }));
  }

  async markRemoved(
    candidate: ChannelMembershipRemovalCandidate,
    runId: string,
  ): Promise<void> {
    const result = await this.#db
      .prepare(
        `UPDATE slack_channel_membership_provenance
         SET removed_by_run_id = ?3, removed_at_ms = ?4
         WHERE channel_id = ?1 AND slack_user_id = ?2 AND removed_at_ms IS NULL
           AND NOT EXISTS (
             SELECT 1 FROM slack_channel_membership_provenance_source source
             WHERE source.channel_id = ?1 AND source.slack_user_id = ?2
               AND source.released_at_ms IS NULL
           )`,
      )
      .bind(candidate.channelId, candidate.slackUserId, runId, Date.now())
      .run();
    if (result.meta.changes !== 1) {
      throw new Error(
        "Slack channel membership provenance changed before removal readback",
      );
    }
  }
}

function parseSourceGoogleGroupIds(json: string): string[] {
  const parsed = SourceGoogleGroupIdsSchema.parse(JSON.parse(json));
  const canonical = [...new Set(parsed)].toSorted((left, right) =>
    left.localeCompare(right),
  );
  if (JSON.stringify(parsed) !== JSON.stringify(canonical)) {
    throw new Error(
      "Slack channel provenance has ambiguous Google source authority",
    );
  }
  return canonical;
}

export async function removeProvenanceQualifiedChannelMemberships(input: {
  allowedChannelIds: ReadonlySet<string>;
  assertNoRenewedSource: (
    candidate: ChannelMembershipRemovalPlan,
    sources: readonly ChannelMembershipProvenanceSource[],
  ) => Promise<void>;
  assertWriteAuthority?: (() => Promise<void>) | undefined;
  beforeMembershipMutation?:
    | ((slackUserIds: readonly string[]) => Promise<void>)
    | undefined;
  candidates: readonly ChannelMembershipRemovalPlan[];
  maxRemovals: number;
  protectedSlackUserIds: ReadonlySet<string>;
  repository: ChannelMembershipProvenanceRepository;
  runId: string;
  slack: ChannelRemovalSlackPort;
}): Promise<number> {
  let removed = 0;
  for (const candidate of input.candidates.slice(
    0,
    Math.max(0, input.maxRemovals),
  )) {
    // eslint-disable-next-line no-await-in-loop -- destructive candidates are intentionally serialized.
    if (await removeOneProvenanceQualifiedChannelMembership(input, candidate))
      removed++;
  }
  return removed;
}

async function removeOneProvenanceQualifiedChannelMembership(
  input: Parameters<typeof removeProvenanceQualifiedChannelMemberships>[0],
  candidate: ChannelMembershipRemovalPlan,
): Promise<boolean> {
  if (
    !input.allowedChannelIds.has(candidate.channelId) ||
    input.protectedSlackUserIds.has(candidate.slackUserId)
  )
    return false;
  const sources = await input.repository.listSources(candidate);
  if (sources.length === 0) return false;
  const before = await input.slack.listChannelMembers(
    candidate.channelId,
    input.runId,
  );
  if (!before.includes(candidate.slackUserId)) {
    await input.repository.markRemoved(candidate, input.runId);
    return false;
  }
  const channel = await input.slack.getChannelRemovalSafety(
    candidate.channelId,
    input.runId,
  );
  if (!matchesRemovalChannelPolicy(channel, candidate)) return false;
  await input.assertNoRenewedSource(candidate, sources);
  if (!(await input.repository.isExclusiveReleasedCandidate(candidate)))
    return false;
  await input.assertWriteAuthority?.();
  await input.beforeMembershipMutation?.([candidate.slackUserId]);
  if (input.beforeMembershipMutation !== undefined) {
    const latestSources = await input.repository.listSources(candidate);
    if (latestSources.length === 0) return false;
    await input.assertNoRenewedSource(candidate, latestSources);
    if (!(await input.repository.isExclusiveReleasedCandidate(candidate)))
      return false;
    const latestChannel = await input.slack.getChannelRemovalSafety(
      candidate.channelId,
      input.runId,
    );
    if (!matchesRemovalChannelPolicy(latestChannel, candidate)) return false;
    await input.assertWriteAuthority?.();
  }
  const { ambiguousKickError, members: after } =
    await kickWithMandatoryReadback(input.slack, candidate, input.runId);
  assertRemovedFromChannel(after, candidate.slackUserId, ambiguousKickError);
  await input.repository.markRemoved(candidate, input.runId);
  return true;
}

function assertRemovedFromChannel(
  members: readonly string[],
  slackUserId: string,
  ambiguousKickError?: SlackWriteOutcomeUnknownError,
): void {
  if (!members.includes(slackUserId)) return;
  if (ambiguousKickError !== undefined) throw ambiguousKickError;
  throw new Error("Slack channel membership removal readback failed");
}

async function kickWithMandatoryReadback(
  slack: ChannelRemovalSlackPort,
  candidate: ChannelMembershipRemovalCandidate,
  runId: string,
): Promise<{
  ambiguousKickError?: SlackWriteOutcomeUnknownError;
  members: string[];
}> {
  let ambiguousKickError: SlackWriteOutcomeUnknownError | undefined;
  try {
    await slack.kick(candidate.channelId, candidate.slackUserId, runId);
  } catch (error) {
    if (!(error instanceof SlackWriteOutcomeUnknownError)) throw error;
    ambiguousKickError = error;
  }
  try {
    return {
      ...(!(ambiguousKickError === undefined) && { ambiguousKickError }),
      members: await slack.listChannelMembers(candidate.channelId, runId),
    };
  } catch (readbackError) {
    if (ambiguousKickError === undefined) throw readbackError;
    throw new AggregateError(
      [ambiguousKickError, readbackError],
      "Slack channel membership removal outcome and readback are both unavailable",
      { cause: readbackError },
    );
  }
}

function matchesRemovalChannelPolicy(
  channel: Awaited<
    ReturnType<ChannelRemovalSlackPort["getChannelRemovalSafety"]>
  >,
  candidate: ChannelMembershipRemovalPlan,
): boolean {
  return (
    channel.id === candidate.channelId &&
    channel.name === candidate.channelName &&
    channel.isPrivate === candidate.isPrivate &&
    channel.isPrivate &&
    !channel.isArchived &&
    !channel.isExternallyShared &&
    channel.name !== "general"
  );
}
