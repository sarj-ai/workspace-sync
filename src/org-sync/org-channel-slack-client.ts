import { z } from "zod";

import { logEvent } from "../shared/log-event.ts";
import { sameStringMultiset } from "../shared/same-string-multiset.ts";
import type {
  SlackChannelIdentity,
  SlackChannelRemovalSafety,
  SlackChannelSnapshot,
  SlackChannelSyncSnapshot,
  SlackUserGroupSnapshot,
} from "./channel-model.ts";
import type { RetryOptions } from "./http.ts";
import type { SlackMember } from "./model.ts";
import {
  parseSlackWriteResponse,
  SlackApiTransport,
} from "./slack-api-transport.ts";

const MAX_SLACK_PAGES = 20;
const AuthTestSchema = z.object({
  ok: z.literal(true),
  "team_id": z.string().regex(/^T[A-Z0-9]+$/u),
  "user_id": z.string().regex(/^[UW][A-Z0-9]+$/u),
});
const ChannelInfoSchema = z.object({
  channel: z.object({
    id: z.string().regex(/^C[A-Z0-9]+$/u),
    "is_archived": z.boolean(),
    "is_private": z.boolean(),
    name: z.string(),
  }),
  ok: z.literal(true),
});
const ChannelRemovalSafetySchema = z.object({
  channel: z.object({
    id: z.string().regex(/^C[A-Z0-9]+$/u),
    "is_archived": z.boolean(),
    "is_ext_shared": z.boolean(),
    "is_private": z.boolean(),
    name: z.string(),
  }),
  ok: z.literal(true),
});
const ChannelIdentitySchema = z.object({
  id: z.string().regex(/^C[A-Z0-9]+$/u),
  "is_archived": z.boolean(),
  "is_private": z.boolean(),
  name: z.string().min(1),
});
const ChannelsPageSchema = z.object({
  channels: z.array(ChannelIdentitySchema),
  ok: z.literal(true),
  "response_metadata": z
    .object({ "next_cursor": z.string().optional() })
    .optional(),
});
const MembersPageSchema = z.object({
  members: z.array(z.string().regex(/^[UW][A-Z0-9]+$/u)),
  ok: z.literal(true),
  "response_metadata": z
    .object({ "next_cursor": z.string().optional() })
    .optional(),
});
const UserGroupSchema = z.object({
  "date_delete": z.number().int().nonnegative(),
  handle: z.string().min(1),
  id: z.string().regex(/^S[A-Z0-9]+$/u),
  name: z.string().min(1),
  prefs: z.object({
    channels: z.array(z.string()),
    groups: z.array(z.string()),
  }),
  users: z.array(z.string().regex(/^[UW][A-Z0-9]+$/u)),
});
const UserGroupCreateResponseSchema = z.object({
  ok: z.literal(true),
  usergroup: z.object({ id: z.string().regex(/^S[A-Z0-9]+$/u) }),
});
const UserGroupsSchema = z.object({
  ok: z.literal(true),
  usergroups: z.array(UserGroupSchema),
});

export interface SlackMembershipFinalSourceAuthority {
  assertFinalSourceAuthority(): Promise<void>;
  assertFreshPlan(): void;
}
const MutationSchema = z.object({ ok: z.literal(true) });
const MAX_HYDRATED_CHANNELS = 80;
const CHANNEL_HYDRATION_CONCURRENCY = 2;

export interface IOrgChannelSlackClient {
  addUserGroupMembers?(
    userGroupId: string,
    handle: string,
    name: string,
    channelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    expectedCurrentUserIds: readonly string[],
    reviewedAdditionUserIds: readonly string[],
    correlationId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
    beforeMembershipMutation?: (
      slackUserIds: readonly string[],
    ) => Promise<void>,
  ): Promise<{ readonly userIds: readonly string[]; readonly wrote: boolean }>;
  createUserGroup?(
    name: string,
    handle: string,
    channelIds: readonly string[],
    runId: string,
    deadlineAt?: number,
  ): Promise<string>;
  getChannelIdentity(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<SlackChannelIdentity>;
  getChannelRemovalSafety?(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<SlackChannelRemovalSafety>;
  getUserGroup?(
    handle: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<null | SlackUserGroupSnapshot>;
  getUserGroupById?(
    id: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<null | SlackUserGroupSnapshot>;
  invite?(
    channelId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    userId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void>;
  kick?(
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
  listMembershipUsers?(
    runId: string,
    deadlineAt?: number,
  ): Promise<SlackMember[]>;
  listSnapshot(
    channelNames: readonly string[],
    runId: string,
    deadlineAt?: number,
    includeUserGroups?: boolean,
    managedUserGroupHandles?: readonly string[],
  ): Promise<SlackChannelSyncSnapshot>;
  removeUserGroupMembers?(
    userGroupId: string,
    handle: string,
    name: string,
    channelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    desiredUserIds: readonly string[],
    expectedCurrentUserIds: readonly string[],
    reviewedRemovalUserIds: readonly string[],
    correlationId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
    beforeMembershipMutation?: (
      slackUserIds: readonly string[],
    ) => Promise<void>,
    finalAuthority?: SlackMembershipFinalSourceAuthority,
  ): Promise<{ readonly userIds: readonly string[]; readonly wrote: boolean }>;
  renameChannel?(
    channelId: string,
    name: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void>;
  updateUserGroup?(
    userGroupId: string,
    name: string,
    handle: string,
    channelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    userIds: readonly string[],
    membershipMode: "additive" | "authoritative",
    correlationId: string,
    deadlineAt?: number,
    expectedCurrentUserIds?: readonly string[],
    reviewedRemovalUserIds?: readonly string[],
    beforeMembershipMutation?: (
      slackUserIds: readonly string[],
    ) => Promise<void>,
    onMutationStart?: () => void,
    expectedCurrentChannelIds?: readonly string[],
    reviewedRemovalChannelIds?: readonly string[],
  ): Promise<void>;
}

export interface OrgChannelSlackClientOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  token: string;
}

export class OrgChannelSlackClient implements IOrgChannelSlackClient {
  readonly #transport: SlackApiTransport;

  constructor(options: OrgChannelSlackClientOptions) {
    this.#transport = new SlackApiTransport(options);
  }

  listMembershipUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<SlackMember[]> {
    return this.#transport.listUsers(runId, deadlineAt);
  }

  async createUserGroup(
    name: string,
    handle: string,
    channelIds: readonly string[],
    runId: string,
    deadlineAt?: number,
  ): Promise<string> {
    const response = await this.#transport.call(
      "usergroups.create",
      { channels: channelIds.join(","), handle, name },
      runId,
      { deadlineAt, post: true },
    );
    return parseSlackWriteResponse(
      UserGroupCreateResponseSchema,
      response.body,
      "usergroups.create",
    ).usergroup.id;
  }

  async getChannelIdentity(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<SlackChannelIdentity> {
    const infoResponse = await this.#transport.call(
      "conversations.info",
      { channel: channelId },
      correlationId,
      { deadlineAt },
    );
    const info = ChannelInfoSchema.parse(infoResponse.body).channel;
    if (info.id !== channelId)
      throw new Error("Slack channel identity readback mismatch");
    return {
      id: info.id,
      isArchived: info["is_archived"],
      isPrivate: info["is_private"],
      name: info.name,
    };
  }

  async getChannelRemovalSafety(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ) {
    const response = await this.#transport.call(
      "conversations.info",
      { channel: channelId },
      correlationId,
      { deadlineAt },
    );
    const channel = ChannelRemovalSafetySchema.parse(response.body).channel;
    return {
      id: channel.id,
      isArchived: channel["is_archived"],
      isExternallyShared: channel["is_ext_shared"],
      isPrivate: channel["is_private"],
      name: channel.name,
    };
  }

  async getUserGroup(
    handle: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<null | SlackUserGroupSnapshot> {
    const userGroups = await this.#readUserGroups(runId, deadlineAt);
    const matches = userGroups.filter((group) => group.handle === handle);
    if (matches.length > 1)
      throw new Error(`Slack user group @${handle} is ambiguous`);
    return matches[0] ?? null;
  }

  async getUserGroupById(
    id: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<null | SlackUserGroupSnapshot> {
    const userGroups = await this.#readUserGroups(runId, deadlineAt);
    const matches = userGroups.filter((group) => group.id === id);
    if (matches.length > 1)
      throw new Error(`Slack user group ${id} is ambiguous`);
    return matches[0] ?? null;
  }

  async invite(
    channelId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    userId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const response = await this.#transport.call(
      "conversations.invite",
      { channel: channelId, users: userId },
      correlationId,
      { deadlineAt, post: true },
    );
    parseSlackWriteResponse(
      MutationSchema,
      response.body,
      "conversations.invite",
    );
  }

  async kick(
    channelId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    userId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const response = await this.#transport.call(
      "conversations.kick",
      { channel: channelId, user: userId },
      correlationId,
      { deadlineAt, post: true },
    );
    parseSlackWriteResponse(
      MutationSchema,
      response.body,
      "conversations.kick",
    );
  }

  async listChannelMembers(
    channelId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<string[]> {
    const members: string[] = [];
    const seenCursors = new Set<string>();
    let cursor = "";
    let page = 0;
    do {
      page++;
      if (page > MAX_SLACK_PAGES)
        throw new Error(`Slack channel ${channelId} exceeded page limit`);
      if (cursor && seenCursors.has(cursor)) {
        throw new Error(
          `Slack channel ${channelId} returned a repeated cursor`,
        );
      }
      if (cursor) seenCursors.add(cursor);
      const params: Record<string, string> = {
        channel: channelId,
        limit: "200",
      };
      if (cursor) params.cursor = cursor;
      // eslint-disable-next-line no-await-in-loop -- Each conversations.members cursor is returned by the preceding page.
      const response = await this.#transport.call(
        "conversations.members",
        params,
        correlationId,
        {
          deadlineAt,
        },
      );
      const parsed = MembersPageSchema.parse(response.body);
      members.push(...parsed.members);
      cursor = parsed["response_metadata"]?.["next_cursor"]?.trim() ?? "";
    } while (cursor);
    return [...new Set(members)].toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    );
  }

  async listSnapshot(
    channelNames: readonly string[],
    runId: string,
    deadlineAt?: number,
    includeUserGroups = false,
    managedUserGroupHandles: readonly string[] = [],
  ): Promise<SlackChannelSyncSnapshot> {
    const authResponse = await this.#transport.call("auth.test", {}, runId, {
      deadlineAt,
    });
    const auth = AuthTestSchema.parse(authResponse.body);
    const scopes = (authResponse.response.headers.get("x-oauth-scopes") ?? "")
      .split(",")
      .map((scope) => scope.trim())
      .filter(Boolean)
      .toSorted();
    const [members, inventory, userGroups] = await Promise.all([
      this.#transport.listUsers(runId, deadlineAt),
      this.#readChannelInventory(runId, deadlineAt),
      includeUserGroups
        ? this.#readUserGroups(runId, deadlineAt)
        : Promise.resolve([]),
    ]);
    const channels: SlackChannelSnapshot[] = [];
    const requestedNames = new Set(channelNames);
    const managedHandleSet = new Set(managedUserGroupHandles);
    const associatedChannelIds = new Set(
      userGroups
        .filter((group) => managedHandleSet.has(group.handle))
        .flatMap((group) => group.channelIds),
    );
    const candidates = inventory.filter(
      (channel) =>
        requestedNames.has(channel.name) ||
        associatedChannelIds.has(channel.id),
    );
    if (candidates.length > MAX_HYDRATED_CHANNELS) {
      throw new Error(
        `Slack channel snapshot exceeds the ${String(MAX_HYDRATED_CHANNELS)} channel safety limit`,
      );
    }
    for (
      let index = 0;
      index < candidates.length;
      index += CHANNEL_HYDRATION_CONCURRENCY
    ) {
      // eslint-disable-next-line no-await-in-loop -- Drain each bounded read batch before advancing or reporting a failure.
      const results = await Promise.allSettled(
        candidates
          .slice(index, index + CHANNEL_HYDRATION_CONCURRENCY)
          .map(async (candidate) => {
            const info = await this.getChannelIdentity(
              candidate.id,
              runId,
              deadlineAt,
            );
            const memberIds = await this.listChannelMembers(
              info.id,
              runId,
              deadlineAt,
            );
            return {
              id: info.id,
              isArchived: info.isArchived,
              isPrivate: info.isPrivate,
              memberIds,
              name: info.name,
            };
          }),
      );
      for (const result of results) {
        if (result.status === "rejected") {
          const failure: unknown = result.reason;
          throw failure instanceof Error
            ? failure
            : new Error("Slack channel hydration failed");
        }
        channels.push(result.value);
      }
    }
    const requestedOrder = new Map(
      channelNames.map((name, index) => [name, index]),
    );
    channels.sort(
      (left, right) =>
        (requestedOrder.get(left.name) ?? Number["MAX_SAFE_INTEGER"]) -
          (requestedOrder.get(right.name) ?? Number["MAX_SAFE_INTEGER"]) ||
        left.id.localeCompare(right.id),
    );
    logEvent("org_channel_sync.slack_snapshot", {
      channels: channels.length,
      "run_id": runId,
      "user_groups": userGroups.length,
      users: members.length,
    });
    return {
      channels,
      inventory,
      members,
      scopes,
      teamId: auth["team_id"],
      userGroups,
    };
  }

  async renameChannel(
    channelId: string,
    name: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void> {
    try {
      const response = await this.#transport.call(
        "conversations.rename",
        { channel: channelId, name },
        correlationId,
        { deadlineAt, post: true },
      );
      parseSlackWriteResponse(
        MutationSchema,
        response.body,
        "conversations.rename",
      );
    } catch (error) {
      const actual = await this.getChannelIdentity(
        channelId,
        correlationId,
        deadlineAt,
      );
      if (actual.name !== name) throw error;
      logEvent("org_channel_sync.mutation_counter", {
        operation: "channel_rename",
        outcome: "ambiguous_recovered",
        "run_id": correlationId,
        value: 1,
      });
      logEvent("org_channel_sync.channel_rename", {
        "channel_id": channelId,
        "expected_name": name,
        phase: "ambiguous_recovered",
        "run_id": correlationId,
      });
    }
  }

  async updateUserGroup(
    userGroupId: string,
    name: string,
    handle: string,
    channelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    userIds: readonly string[],
    membershipMode: "additive" | "authoritative",
    correlationId: string,
    deadlineAt?: number,
    expectedCurrentUserIds?: readonly string[],
    reviewedRemovalUserIds?: readonly string[],
    beforeMembershipMutation?: (
      slackUserIds: readonly string[],
    ) => Promise<void>,
    onMutationStart?: () => void,
    expectedCurrentChannelIds?: readonly string[],
    reviewedRemovalChannelIds?: readonly string[],
  ): Promise<void> {
    const beforeProfile = await this.getUserGroupById(
      userGroupId,
      correlationId,
      deadlineAt,
    );
    if (!beforeProfile)
      throw new Error(
        `Slack user group ${userGroupId} disappeared before update`,
      );
    const hasReviewedRemovals = (reviewedRemovalUserIds?.length ?? 0) > 0;
    if (
      hasReviewedRemovals &&
      !sameStringMultiset(beforeProfile.channelIds, channelIds)
    ) {
      throw new Error(
        `Slack user group @${handle} gained an unreviewed channel association before removal`,
      );
    }
    const finalChannelIds = buildFinalUserGroupChannels(
      channelIds,
      beforeProfile.channelIds,
      expectedCurrentChannelIds,
      reviewedRemovalChannelIds,
      handle,
    );
    const previewUserIds = buildFinalUserGroupMembership(
      membershipMode,
      userIds,
      beforeProfile.userIds,
      expectedCurrentUserIds,
      reviewedRemovalUserIds,
      handle,
    );
    await beforeMembershipMutation?.(
      membershipDifference(beforeProfile.userIds, previewUserIds),
    );
    await this.#assertUnchangedBudgetedGroup(
      beforeProfile,
      correlationId,
      deadlineAt,
      beforeMembershipMutation !== undefined,
    );
    await this.#updateUserGroupProfile(
      beforeProfile,
      userGroupId,
      name,
      handle,
      finalChannelIds,
      correlationId,
      deadlineAt,
      onMutationStart,
    );
    const beforeMembers = await this.getUserGroup(
      handle,
      correlationId,
      deadlineAt,
    );
    if (beforeMembers?.id !== userGroupId) {
      throw new Error(
        `Slack user group @${handle} disappeared before membership update`,
      );
    }
    if (
      hasReviewedRemovals &&
      !sameStringMultiset(beforeMembers.channelIds, channelIds)
    ) {
      throw new Error(
        `Slack user group @${handle} gained an unreviewed channel association before removal`,
      );
    }
    const finalUserIds = buildFinalUserGroupMembership(
      membershipMode,
      userIds,
      beforeMembers.userIds,
      expectedCurrentUserIds,
      reviewedRemovalUserIds,
      handle,
    );
    if (
      sameStringMultiset(beforeMembers.userIds, finalUserIds) ||
      finalUserIds.length === 0
    )
      return;
    await beforeMembershipMutation?.(
      membershipDifference(beforeMembers.userIds, finalUserIds),
    );
    if (beforeMembershipMutation !== undefined)
      await this.#assertUnchangedBudgetedGroup(
        beforeMembers,
        correlationId,
        deadlineAt,
      );
    onMutationStart?.();
    try {
      const membersResponse = await this.#transport.call(
        "usergroups.users.update",
        { usergroup: userGroupId, users: finalUserIds.join(",") },
        correlationId,
        { deadlineAt, post: true },
      );
      parseSlackWriteResponse(
        MutationSchema,
        membersResponse.body,
        "usergroups.users.update",
      );
    } catch (error) {
      const actual = await this.getUserGroup(handle, correlationId, deadlineAt);
      if (
        actual?.id !== userGroupId ||
        !sameStringMultiset(actual.userIds, finalUserIds)
      )
        throw error;
    }
  }

  async removeUserGroupMembers(
    userGroupId: string,
    handle: string,
    name: string,
    channelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    desiredUserIds: readonly string[],
    expectedCurrentUserIds: readonly string[],
    reviewedRemovalUserIds: readonly string[],
    correlationId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
    beforeMembershipMutation?: (
      slackUserIds: readonly string[],
    ) => Promise<void>,
    finalAuthority?: SlackMembershipFinalSourceAuthority,
  ): Promise<{ readonly userIds: readonly string[]; readonly wrote: boolean }> {
    const before = await this.getUserGroupById(
      userGroupId,
      correlationId,
      deadlineAt,
    );
    if (
      before?.handle !== handle ||
      before.isDisabled ||
      before.name !== name ||
      !sameStringMultiset(before.channelIds, channelIds)
    ) {
      throw new Error(
        `Slack user group @${handle} changed before removal-only update`,
      );
    }
    const finalUserIds = buildFinalUserGroupMembership(
      "authoritative",
      desiredUserIds,
      before.userIds,
      expectedCurrentUserIds,
      reviewedRemovalUserIds,
      handle,
    );
    if (finalUserIds.length === 0) {
      throw new Error(
        `Slack user group @${handle} removal-only update would empty membership`,
      );
    }
    if (sameStringMultiset(before.userIds, finalUserIds))
      return { userIds: finalUserIds, wrote: false };
    await beforeMembershipMutation?.(
      membershipDifference(before.userIds, finalUserIds),
    );
    if (beforeMembershipMutation !== undefined)
      await this.#assertUnchangedBudgetedGroup(
        before,
        correlationId,
        deadlineAt,
      );
    if (finalAuthority !== undefined) {
      if (beforeMembershipMutation === undefined)
        throw new Error("slack_reviewed_membership_budget_required");
      await finalAuthority.assertFinalSourceAuthority();
      finalAuthority.assertFreshPlan();
    }
    onMutationStart?.();
    try {
      const response = await this.#transport.call(
        "usergroups.users.update",
        { usergroup: userGroupId, users: finalUserIds.join(",") },
        correlationId,
        { deadlineAt, post: true },
      );
      parseSlackWriteResponse(
        MutationSchema,
        response.body,
        "usergroups.users.update",
      );
    } catch (error) {
      const actual = await this.getUserGroupById(
        userGroupId,
        correlationId,
        deadlineAt,
      );
      if (
        actual?.handle !== handle ||
        actual.isDisabled ||
        actual.name !== name ||
        !sameStringMultiset(actual.channelIds, channelIds) ||
        !sameStringMultiset(actual.userIds, finalUserIds)
      ) {
        throw error;
      }
    }
    return { userIds: finalUserIds, wrote: true };
  }

  async addUserGroupMembers(
    userGroupId: string,
    handle: string,
    name: string,
    channelIds: readonly string[],
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- This Slack transport contract retains SDK string IDs; signed authority, membership budgets and readbacks guard writes.
    expectedCurrentUserIds: readonly string[],
    reviewedAdditionUserIds: readonly string[],
    correlationId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
    beforeMembershipMutation?: (
      slackUserIds: readonly string[],
    ) => Promise<void>,
  ): Promise<{ readonly userIds: readonly string[]; readonly wrote: boolean }> {
    if (
      reviewedAdditionUserIds.length === 0 ||
      new Set(reviewedAdditionUserIds).size !== reviewedAdditionUserIds.length
    ) {
      throw new Error(
        `Slack user group @${handle} addition-only update is not an exact batch`,
      );
    }
    const before = await this.getUserGroupById(
      userGroupId,
      correlationId,
      deadlineAt,
    );
    if (
      before?.handle !== handle ||
      before.isDisabled ||
      before.name !== name ||
      !sameStringMultiset(before.channelIds, channelIds)
    ) {
      throw new Error(
        `Slack user group @${handle} changed before addition-only update`,
      );
    }
    const beforeUserIds = new Set(before.userIds);
    if (expectedCurrentUserIds.some((userId) => !beforeUserIds.has(userId))) {
      throw new Error(
        `Slack user group @${handle} lost a planned member before addition-only update`,
      );
    }
    const finalUserIds = mergeUniqueStrings(
      before.userIds,
      reviewedAdditionUserIds,
    ).toSorted((left, right) => left.localeCompare(right));
    if (sameStringMultiset(before.userIds, finalUserIds))
      return { userIds: finalUserIds, wrote: false };
    await beforeMembershipMutation?.(
      membershipDifference(before.userIds, finalUserIds),
    );
    if (beforeMembershipMutation !== undefined)
      await this.#assertUnchangedBudgetedGroup(
        before,
        correlationId,
        deadlineAt,
      );
    onMutationStart?.();
    try {
      const response = await this.#transport.call(
        "usergroups.users.update",
        { usergroup: userGroupId, users: finalUserIds.join(",") },
        correlationId,
        { deadlineAt, post: true },
      );
      parseSlackWriteResponse(
        MutationSchema,
        response.body,
        "usergroups.users.update",
      );
    } catch (error) {
      const actual = await this.getUserGroupById(
        userGroupId,
        correlationId,
        deadlineAt,
      );
      if (
        actual?.handle !== handle ||
        actual.isDisabled ||
        actual.name !== name ||
        !sameStringMultiset(actual.channelIds, channelIds) ||
        !sameStringMultiset(actual.userIds, finalUserIds)
      ) {
        throw error;
      }
    }
    return { userIds: finalUserIds, wrote: true };
  }

  async #readChannelInventory(
    runId: string,
    deadlineAt?: number,
  ): Promise<SlackChannelIdentity[]> {
    const channels: SlackChannelIdentity[] = [];
    const seenCursors = new Set<string>();
    let cursor = "";
    let page = 0;
    do {
      page++;
      if (page > MAX_SLACK_PAGES)
        throw new Error("Slack conversations.list exceeded page limit");
      if (cursor && seenCursors.has(cursor)) {
        throw new Error("Slack conversations.list repeated a cursor");
      }
      if (cursor) seenCursors.add(cursor);
      const params: Record<string, string> = {
        "exclude_archived": "false",
        limit: "200",
        types: "public_channel,private_channel",
      };
      if (cursor) params.cursor = cursor;
      // eslint-disable-next-line no-await-in-loop -- Each conversations.list cursor is returned by the preceding page.
      const response = await this.#transport.call(
        "conversations.list",
        params,
        runId,
        {
          deadlineAt,
        },
      );
      const parsed = ChannelsPageSchema.parse(response.body);
      channels.push(
        ...parsed.channels.map((channel) => ({
          id: channel.id,
          isArchived: channel["is_archived"],
          isPrivate: channel["is_private"],
          name: channel.name,
        })),
      );
      cursor = parsed["response_metadata"]?.["next_cursor"]?.trim() ?? "";
    } while (cursor);
    return channels.toSorted((left, right) =>
      left.name.localeCompare(right.name),
    );
  }

  async #readUserGroups(
    runId: string,
    deadlineAt?: number,
  ): Promise<SlackUserGroupSnapshot[]> {
    const response = await this.#transport.call(
      "usergroups.list",
      { "include_disabled": true, "include_users": true },
      runId,
      { deadlineAt },
    );
    const parsed = UserGroupsSchema.parse(response.body);
    return parsed.usergroups
      .map((userGroup) => {
        const channelIds = new Set(userGroup.prefs.channels);
        for (const channelId of userGroup.prefs.groups)
          channelIds.add(channelId);
        return {
          channelIds: channelIds
            .values()
            .toArray()
            .toSorted((left, right) => left.localeCompare(right)),
          handle: userGroup.handle,
          id: userGroup.id,
          isDisabled: userGroup["date_delete"] > 0,
          name: userGroup.name,
          userIds: new Set(userGroup.users)
            .values()
            .toArray()
            .toSorted((left, right) => left.localeCompare(right)),
        };
      })
      .toSorted((left, right) => left.handle.localeCompare(right.handle));
  }

  async #assertUnchangedBudgetedGroup(
    before: SlackUserGroupSnapshot,
    runId: string,
    deadlineAt?: number,
    required = true,
  ): Promise<void> {
    if (!required) return;
    const after = await this.getUserGroupById(before.id, runId, deadlineAt);
    if (
      after?.id !== before.id ||
      after.handle !== before.handle ||
      after.name !== before.name ||
      after.isDisabled !== before.isDisabled ||
      !sameStringMultiset(after.userIds, before.userIds) ||
      !sameStringMultiset(after.channelIds, before.channelIds)
    )
      throw new Error("slack_budget_provider_group_changed");
  }

  async #updateUserGroupProfile(
    before: SlackUserGroupSnapshot,
    userGroupId: string,
    name: string,
    handle: string,
    channelIds: readonly string[],
    correlationId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
  ): Promise<void> {
    if (
      before.handle === handle &&
      before.name === name &&
      sameStringMultiset(before.channelIds, channelIds)
    ) {
      return;
    }
    onMutationStart?.();
    try {
      const response = await this.#transport.call(
        "usergroups.update",
        {
          channels: channelIds.join(","),
          handle,
          name,
          usergroup: userGroupId,
        },
        correlationId,
        { deadlineAt, post: true },
      );
      parseSlackWriteResponse(
        MutationSchema,
        response.body,
        "usergroups.update",
      );
    } catch (error) {
      const actual = await this.getUserGroup(handle, correlationId, deadlineAt);
      if (
        actual?.id !== userGroupId ||
        actual.name !== name ||
        !sameStringMultiset(actual.channelIds, channelIds)
      ) {
        throw error;
      }
    }
  }
}

function buildFinalUserGroupChannels(
  desiredChannelIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Both collections contain Slack channel IDs; their qualifiers describe states of the same identity role.
  latestChannelIds: readonly string[],
  expectedCurrentChannelIds: readonly string[] | undefined,
  reviewedRemovalChannelIds: readonly string[] | undefined,
  handle: string,
): string[] {
  const reviewedRemovalIds = reviewedRemovalChannelIds ?? [];
  if (reviewedRemovalIds.length === 0) {
    return mergeUniqueStrings(desiredChannelIds, latestChannelIds).toSorted(
      (left, right) => left.localeCompare(right),
    );
  }
  if (expectedCurrentChannelIds === undefined) {
    throw new Error(
      `Slack user group @${handle} lacks a reviewed channel snapshot`,
    );
  }
  const expected = new Set(expectedCurrentChannelIds);
  const reviewed = new Set(reviewedRemovalIds);
  const desired = new Set(desiredChannelIds);
  if (
    reviewed.size !== reviewedRemovalIds.length ||
    reviewedRemovalIds.some(
      (channelId) => !expected.has(channelId) || desired.has(channelId),
    )
  ) {
    throw new Error(
      `Slack user group @${handle} channel removal review is inconsistent`,
    );
  }
  const latest = new Set(latestChannelIds);
  if (
    expectedCurrentChannelIds.some(
      (channelId) => !latest.has(channelId) && !reviewed.has(channelId),
    )
  ) {
    throw new Error(
      `Slack user group @${handle} lost an unreviewed channel association before update`,
    );
  }
  return mergeUniqueStrings(
    desiredChannelIds,
    latestChannelIds.filter((channelId) => !reviewed.has(channelId)),
  ).toSorted((left, right) => left.localeCompare(right));
}

function buildFinalUserGroupMembership(
  membershipMode: "additive" | "authoritative",
  desiredUserIds: readonly string[],
  // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Both collections contain Slack user IDs; their qualifiers describe states of the same identity role.
  latestUserIds: readonly string[],
  expectedCurrentUserIds: readonly string[] | undefined,
  reviewedRemovalUserIds: readonly string[] | undefined,
  handle: string,
): string[] {
  if (membershipMode === "additive")
    return mergeUniqueStrings(desiredUserIds, latestUserIds);
  if (expectedCurrentUserIds === undefined) {
    throw new Error(
      `Slack user group @${handle} lacks an authoritative plan snapshot`,
    );
  }
  if (reviewedRemovalUserIds === undefined) {
    throw new Error(
      `Slack user group @${handle} lacks an explicit reviewed removal set`,
    );
  }
  const desired = new Set(desiredUserIds);
  const latest = new Set(latestUserIds);
  const expectedCurrent = new Set(expectedCurrentUserIds);
  const reviewedRemovals = new Set(reviewedRemovalUserIds);
  if (
    reviewedRemovals
      .values()
      .some((userId) => !expectedCurrent.has(userId) || desired.has(userId))
  ) {
    throw new Error(
      `Slack user group @${handle} has an invalid reviewed removal set`,
    );
  }
  const unexpectedlyMissing = expectedCurrentUserIds.filter(
    (userId) => !reviewedRemovals.has(userId) && !latest.has(userId),
  );
  if (unexpectedlyMissing.length > 0) {
    throw new Error(
      `Slack user group @${handle} lost unreviewed members before update`,
    );
  }
  return [
    ...latestUserIds.filter((userId) => !reviewedRemovals.has(userId)),
    ...desiredUserIds.filter((userId) => !latest.has(userId)),
  ].toSorted((left, right) => left.localeCompare(right));
}

function membershipDifference(
  before: readonly string[],
  after: readonly string[],
): string[] {
  const beforeIds = new Set(before);
  const afterIds = new Set(after);
  return [...beforeIds.difference(afterIds), ...afterIds.difference(beforeIds)];
}

function mergeUniqueStrings(
  existing: readonly string[],
  required: readonly string[],
): string[] {
  const result = new Set(existing);
  for (const value of required) result.add(value);
  return result
    .values()
    .toArray()
    .toSorted((left, right) => left.localeCompare(right));
}
