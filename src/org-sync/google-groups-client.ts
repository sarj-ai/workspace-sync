import { z } from "zod";

import { contractorAuthorityGroup } from "../identity-provisioning/employee-entitlement-policy.ts";
import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";
import { logEvent } from "../shared/log-event.ts";
import {
  type GoogleGroupIdentity,
  GoogleGroupIdentitySchema,
  type GoogleGroupMember,
  GoogleGroupMemberSchema,
  type GoogleGroupSnapshot,
} from "./channel-model.ts";
import {
  GoogleDelegatedAuth,
  type GoogleDelegatedAuthOptions,
} from "./google-delegated-auth.ts";
import { GoogleGroupMembersPageSchema } from "./google-group-members.ts";
import { fetchWithRetry } from "./http.ts";

const DIRECTORY_GROUPS_ENDPOINT =
  "https://admin.googleapis.com/admin/directory/v1/groups";
const GROUPS_READ_SCOPE =
  "https://www.googleapis.com/auth/admin.directory.group.readonly";
const GROUP_MEMBERS_WRITE_SCOPES = [
  GROUPS_READ_SCOPE,
  "https://www.googleapis.com/auth/admin.directory.group.member",
].join(" ");
const GROUP_READ_CONCURRENCY = 4;
const MAX_GROUP_PAGES = 20;
const MAX_MEMBER_PAGES = 20;
const MAX_RECURSIVE_GROUPS = 50;

const GroupsPageSchema = z.object({
  groups: z.array(GoogleGroupIdentitySchema).default([]),
  nextPageToken: z.string().optional(),
});
export interface IGoogleGroupsClient {
  listAllGroups(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupIdentity[]>;
  listGroups(
    groupKeys: readonly string[],
    runId: string,
    deadlineAt?: number,
    expandNested?: boolean,
    preserveResolvedPrimaryEmail?: boolean,
  ): Promise<GoogleGroupSnapshot[]>;
}

export interface GoogleGroupsClientOptions extends GoogleDelegatedAuthOptions {
  userProject: string;
}

export interface GoogleGroupDirectMembershipRemoval {
  groupEmail: string;
  groupId: string;
  memberEmail: string;
  memberId: string;
  role?: "MANAGER" | "OWNER";
}

export interface GoogleGroupPrivilegedMembershipRemoval extends GoogleGroupDirectMembershipRemoval {
  role: "MANAGER" | "OWNER";
}

export interface IGoogleGroupPrivilegedMembershipWriter {
  auditPrivilegedDirectMember(
    target: GoogleGroupPrivilegedMembershipRemoval,
    runId: string,
    deadlineAt?: number,
  ): Promise<void>;
  removePrivilegedDirectMember(
    target: GoogleGroupPrivilegedMembershipRemoval,
    runId: string,
    deadlineAt?: number,
  ): Promise<{ readonly wrote: boolean }>;
}

export interface GoogleGroupRemovalParentAuthority {
  assertFinalSourceAuthority(): Promise<void>;
  assertFreshPlan(): void;
  assertWriteAuthority(): Promise<void>;
}

export interface IGoogleGroupMembershipWriter {
  auditDirectMember(
    target: GoogleGroupDirectMembershipRemoval,
    runId: string,
    deadlineAt?: number,
  ): Promise<void>;
  removeDirectMember(
    target: GoogleGroupDirectMembershipRemoval,
    runId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
    parentAuthority?: GoogleGroupRemovalParentAuthority,
  ): Promise<{ readonly wrote: boolean }>;
}

/**
 * Deliberately separate from the snapshot reader so scheduled cleanup cannot
 * accidentally gain a general-purpose Google Groups mutation surface.
 */
export class GoogleGroupMembershipWriter
  implements
    IGoogleGroupMembershipWriter,
    IGoogleGroupPrivilegedMembershipWriter
{
  readonly #auth: GoogleDelegatedAuth;
  readonly #options: GoogleGroupsClientOptions;

  constructor(options: GoogleGroupsClientOptions) {
    this.#options = Object.freeze({ ...options });
    this.#auth = new GoogleDelegatedAuth(options);
  }

  async auditDirectMember(
    target: GoogleGroupDirectMembershipRemoval,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const token = await this.#auth.accessToken(
      GROUP_MEMBERS_WRITE_SCOPES,
      runId,
      deadlineAt,
    );
    await this.#assertExactTarget(
      target,
      target.role ?? "MEMBER",
      token,
      runId,
      deadlineAt,
      false,
    );
  }

  async auditPrivilegedDirectMember(
    target: GoogleGroupPrivilegedMembershipRemoval,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const token = await this.#auth.accessToken(
      GROUP_MEMBERS_WRITE_SCOPES,
      runId,
      deadlineAt,
    );
    await this.#assertExactTarget(
      target,
      target.role,
      token,
      runId,
      deadlineAt,
    );
  }

  async removeDirectMember(
    target: GoogleGroupDirectMembershipRemoval,
    runId: string,
    deadlineAt?: number,
    onMutationStart?: () => void,
    parentAuthority?: GoogleGroupRemovalParentAuthority,
  ): Promise<{ readonly wrote: boolean }> {
    if (target.role !== undefined && parentAuthority === undefined) {
      throw new Error(
        "Google privileged offboarding requires signed parent authority",
      );
    }
    const token = await this.#auth.accessToken(
      GROUP_MEMBERS_WRITE_SCOPES,
      runId,
      deadlineAt,
    );
    const role = target.role ?? "MEMBER";
    // Offboarding may remove the inactive sole owner: Workspace administrators
    // retain group administration. The signed parent rechecks lifecycle below.
    await this.#assertExactTarget(
      target,
      role,
      token,
      runId,
      deadlineAt,
      false,
    );

    if (parentAuthority !== undefined) {
      await parentAuthority.assertWriteAuthority();
      await this.#assertExactTarget(
        target,
        role,
        token,
        runId,
        deadlineAt,
        false,
      );
      await parentAuthority.assertFinalSourceAuthority();
      parentAuthority.assertFreshPlan();
    }
    onMutationStart?.();
    let mutationError: Error | undefined;
    try {
      const response = await this.#requestDirectory(
        this.#memberUrl(target.groupId, target.memberId),
        token,
        "google.directory.members.delete",
        runId,
        deadlineAt,
        { method: "DELETE" },
        parentAuthority === undefined ? undefined : 1,
      );
      if (!response.ok) {
        response.body?.cancel().catch(() => null);
        throw new Error(
          `google.directory.members.delete HTTP ${String(response.status)}`,
        );
      }
      await response.body?.cancel();
    } catch (error) {
      mutationError = error instanceof Error ? error : new Error(String(error));
    }

    const readback = await this.#readMemberIfPresent(
      target.groupId,
      target.memberId,
      token,
      runId,
      deadlineAt,
    );
    if (readback === null) {
      await this.#assertExactGroup(target, token, runId, deadlineAt);
      return { wrote: true };
    }
    if (mutationError !== undefined) throw mutationError;
    throw new Error(
      "Google group member remained after direct-membership removal",
    );
  }

  async removePrivilegedDirectMember(
    target: GoogleGroupPrivilegedMembershipRemoval,
    runId: string,
    deadlineAt?: number,
  ): Promise<{ readonly wrote: boolean }> {
    const token = await this.#auth.accessToken(
      GROUP_MEMBERS_WRITE_SCOPES,
      runId,
      deadlineAt,
    );
    // This is the final provider read immediately before the bounded DELETE.
    await this.#assertExactTarget(
      target,
      target.role,
      token,
      runId,
      deadlineAt,
    );
    let mutationError: Error | undefined;
    try {
      const response = await this.#requestDirectory(
        this.#memberUrl(target.groupId, target.memberId),
        token,
        "google.directory.members.delete_privileged",
        runId,
        deadlineAt,
        { method: "DELETE" },
        1,
      );
      if (!response.ok) {
        response.body?.cancel().catch(() => null);
        throw new Error(
          `google.directory.members.delete_privileged HTTP ${String(response.status)}`,
        );
      }
      await response.body?.cancel();
    } catch (error) {
      mutationError = error instanceof Error ? error : new Error(String(error));
    }
    const readback = await this.#readMemberIfPresent(
      target.groupId,
      target.memberId,
      token,
      runId,
      deadlineAt,
    );
    if (readback === null) {
      await this.#assertExactGroup(target, token, runId, deadlineAt);
      return { wrote: true };
    }
    if (mutationError !== undefined) throw mutationError;
    throw new Error("Google privileged group member remained after removal");
  }

  async #assertExactTarget(
    target: GoogleGroupDirectMembershipRemoval,
    expectedRole: GoogleGroupMember["role"],
    token: string,
    runId: string,
    deadlineAt?: number,
    requireOwnerQuorum = true,
  ): Promise<void> {
    await this.#assertExactGroup(target, token, runId, deadlineAt);
    const member = await this.#readMember(
      target.groupId,
      target.memberId,
      token,
      runId,
      deadlineAt,
    );
    if (
      member.id !== target.memberId ||
      member.type !== "USER" ||
      member.role !== expectedRole ||
      normalizeEmail(member.email) !== normalizeEmail(target.memberEmail)
    ) {
      throw new Error(
        "Google group member changed before direct-membership removal",
      );
    }
    if (expectedRole === "OWNER" && requireOwnerQuorum) {
      const owners = await this.#listDirectOwnerIds(
        target.groupId,
        token,
        runId,
        deadlineAt,
      );
      if (!owners.has(target.memberId) || owners.size < 2) {
        throw new Error(
          "Google group owner removal requires at least two direct owners",
        );
      }
    }
  }

  async #assertExactGroup(
    target: GoogleGroupDirectMembershipRemoval,
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const group = await this.#readGroup(
      target.groupId,
      token,
      runId,
      deadlineAt,
    );
    if (
      group.id !== target.groupId ||
      normalizeEmail(group.email) !== normalizeEmail(target.groupEmail)
    ) {
      throw new Error("Google group changed before direct-membership removal");
    }
  }

  async #listDirectOwnerIds(
    groupId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<Set<string>> {
    const owners = new Set<string>();
    const seenPageTokens = new Set<string>();
    let pageToken = "";
    let page = 0;
    do {
      page++;
      if (page > MAX_MEMBER_PAGES) {
        throw new Error(
          `Google group ${groupId} owner listing exceeded page limit`,
        );
      }
      recordOwnerPageToken(groupId, pageToken, seenPageTokens);
      const query = new URLSearchParams({ maxResults: "200", roles: "OWNER" });
      if (pageToken) query.set("pageToken", pageToken);
      // eslint-disable-next-line no-await-in-loop -- The next owner page token comes from the current response.
      const parsed = await this.#readOwnerPage(
        groupId,
        query,
        token,
        correlationId,
        deadlineAt,
      );
      addDirectOwners(owners, parsed.members);
      pageToken = parsed.nextPageToken ?? "";
    } while (pageToken);
    return owners;
  }

  async #readOwnerPage(
    groupId: string,
    query: URLSearchParams,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<z.output<typeof GoogleGroupMembersPageSchema>> {
    const response = await this.#requestDirectory(
      `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(groupId)}/members?${query.toString()}`,
      token,
      "google.directory.members.list_owners_for_removal",
      correlationId,
      deadlineAt,
    );
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(
        `google.directory.members.list_owners_for_removal HTTP ${String(response.status)}`,
      );
    }
    return GoogleGroupMembersPageSchema.parse(await response.json());
  }

  #memberUrl(
    groupId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Directory resource keys can be IDs or email aliases; retain raw transport strings and validate the returned resources.
    memberId: string,
  ): string {
    return `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(groupId)}/members/${encodeURIComponent(memberId)}`;
  }

  async #readGroup(
    groupId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupIdentity> {
    const response = await this.#requestDirectory(
      `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(groupId)}`,
      token,
      "google.directory.groups.get_for_member_removal",
      correlationId,
      deadlineAt,
    );
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(
        `google.directory.groups.get_for_member_removal HTTP ${String(response.status)}`,
      );
    }
    return GoogleGroupIdentitySchema.parse(await response.json());
  }

  async #readMember(
    groupId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Directory resource keys can be IDs or email aliases; retain raw transport strings and validate the returned resources.
    memberId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupMember> {
    const member = await this.#readMemberIfPresent(
      groupId,
      memberId,
      token,
      correlationId,
      deadlineAt,
    );
    if (member === null) {
      throw new Error(
        "Google group member was absent before direct-membership removal",
      );
    }
    return member;
  }

  async #readMemberIfPresent(
    groupId: string,
    // eslint-disable-next-line @sarj/prefer-nominal-id-types -- Directory resource keys can be IDs or email aliases; retain raw transport strings and validate the returned resources.
    memberId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupMember | null> {
    const response = await this.#requestDirectory(
      this.#memberUrl(groupId, memberId),
      token,
      "google.directory.members.get_for_removal",
      correlationId,
      deadlineAt,
    );
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(
        `google.directory.members.get_for_removal HTTP ${String(response.status)}`,
      );
    }
    return GoogleGroupMemberSchema.parse(await response.json());
  }

  #requestDirectory(
    url: string,
    token: string,
    label: string,
    runId: string,
    deadlineAt?: number,
    init: RequestInit = {},
    maxAttempts?: number,
  ): Promise<Response> {
    return fetchWithRetry(
      url,
      {
        ...init,
        headers: {
          ...Object.fromEntries(new Headers(init.headers).entries()),
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        ...(!(maxAttempts === undefined) && { maxAttempts }),
        fetchImpl: this.#options.fetchImpl,
        label,
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
  }
}

export class GoogleGroupsClient implements IGoogleGroupsClient {
  readonly #auth: GoogleDelegatedAuth;
  readonly #options: GoogleGroupsClientOptions;

  constructor(options: GoogleGroupsClientOptions) {
    this.#options = Object.freeze({ ...options });
    this.#auth = new GoogleDelegatedAuth(options);
  }

  async listAllGroups(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupIdentity[]> {
    const token = await this.#auth.accessToken(
      GROUPS_READ_SCOPE,
      runId,
      deadlineAt,
    );
    const groups: GoogleGroupIdentity[] = [];
    const seenPageTokens = new Set<string>();
    let pageToken = "";
    let page = 0;
    do {
      page++;
      if (page > MAX_GROUP_PAGES)
        throw new Error("Google groups.list exceeded page limit");
      if (pageToken && seenPageTokens.has(pageToken)) {
        throw new Error("Google groups.list returned a repeated page token");
      }
      if (pageToken) seenPageTokens.add(pageToken);
      const query = new URLSearchParams({
        customer: "my_customer",
        maxResults: "200",
      });
      if (pageToken) query.set("pageToken", pageToken);
      // eslint-disable-next-line no-await-in-loop -- Each groups.list page token is returned by the preceding response.
      const response = await this.#requestDirectory(
        `${DIRECTORY_GROUPS_ENDPOINT}?${query.toString()}`,
        token,
        "google.directory.groups.list",
        runId,
        deadlineAt,
      );
      // eslint-disable-next-line no-await-in-loop -- The current response body must be parsed before its next-page token is available.
      const parsed = GroupsPageSchema.parse(await response.json());
      groups.push(...parsed.groups);
      pageToken = parsed.nextPageToken ?? "";
    } while (pageToken);
    return groups.toSorted((left, right) =>
      left.email.localeCompare(right.email),
    );
  }

  async listGroups(
    groupKeys: readonly string[],
    runId: string,
    deadlineAt?: number,
    expandNested = false,
    preserveResolvedPrimaryEmail = false,
  ): Promise<GoogleGroupSnapshot[]> {
    const token = await this.#auth.accessToken(
      GROUPS_READ_SCOPE,
      runId,
      deadlineAt,
    );
    const groups: GoogleGroupSnapshot[] = expandNested
      ? []
      : await this.#listDirectGroups(
          groupKeys,
          token,
          runId,
          deadlineAt,
          preserveResolvedPrimaryEmail,
        );
    const pendingGroupKeys = expandNested ? [...groupKeys] : [];
    const queuedGroupKeys = new Set(groupKeys.map(normalizeEmail));
    const seenGroupIds = new Set<string>();
    for (const groupKey of pendingGroupKeys) {
      // eslint-disable-next-line no-await-in-loop -- Each configured group must resolve before duplicate immutable IDs can be rejected.
      const groupIdentity = await this.#resolveConfiguredGroup(
        groupKey,
        token,
        runId,
        deadlineAt,
        preserveResolvedPrimaryEmail,
      );
      if (seenGroupIds.has(groupIdentity.id)) {
        if (expandNested) continue;
        throw new Error(
          `Multiple configured Google groups resolved to immutable ID ${groupIdentity.id}`,
        );
      }
      seenGroupIds.add(groupIdentity.id);
      // eslint-disable-next-line no-await-in-loop -- Nested group keys are discovered from the current membership response.
      const members = await this.#listMembers(
        groupIdentity.id,
        token,
        runId,
        deadlineAt,
      );
      const group = { ...groupIdentity, members };
      groups.push(group);
      if (expandNested)
        this.#enqueueNestedGroupKeys(group, pendingGroupKeys, queuedGroupKeys);
    }
    logEvent(
      `${this.#options.operation ?? "org_channel_sync"}.google_snapshot`,
      {
        groups: groups.length,
        members: groups.reduce(
          (total, group) => total + group.members.length,
          0,
        ),
        "run_id": runId,
      },
    );
    return groups;
  }

  async #listDirectGroups(
    groupKeys: readonly string[],
    token: string,
    runId: string,
    deadlineAt: number | undefined,
    preserveResolvedPrimaryEmail: boolean,
  ): Promise<GoogleGroupSnapshot[]> {
    const identities = await readGroupBatches(groupKeys, (key) =>
      this.#resolveConfiguredGroup(
        key,
        token,
        runId,
        deadlineAt,
        preserveResolvedPrimaryEmail,
      ),
    );
    const ids = new Set<string>();
    for (const identity of identities) {
      if (ids.has(identity.id))
        throw new Error(
          `Multiple configured Google groups resolved to immutable ID ${identity.id}`,
        );
      ids.add(identity.id);
    }
    return readGroupBatches(identities, async (identity) => ({
      ...identity,
      members: await this.#listMembers(identity.id, token, runId, deadlineAt),
    }));
  }

  async #resolveConfiguredGroup(
    groupKey: string,
    token: string,
    runId: string,
    deadlineAt?: number,
    preserveResolvedPrimaryEmail = false,
  ): Promise<GoogleGroupIdentity> {
    const contractorAuthority = isContractorAuthorityEmail(groupKey);
    const lookupKey = contractorAuthority
      ? contractorAuthorityGroup().id
      : groupKey;
    const resolved = await this.#readGroup(lookupKey, token, runId, deadlineAt);
    if (
      contractorAuthority &&
      (resolved.id !== contractorAuthorityGroup().id ||
        !isContractorAuthorityEmail(resolved.email))
    ) {
      throw new Error(
        "Configured contractor group resolved to an unexpected authority",
      );
    }
    if (
      !contractorAuthority &&
      normalizeEmail(resolved.email) !== normalizeEmail(groupKey)
    ) {
      throw new Error(
        `Google group ${groupKey} resolved to a different primary address`,
      );
    }
    return contractorAuthority && !preserveResolvedPrimaryEmail
      ? { ...resolved, email: contractorAuthorityGroup().email }
      : resolved;
  }

  #enqueueNestedGroupKeys(
    group: GoogleGroupSnapshot,
    pendingGroupKeys: string[],
    queuedGroupKeys: Set<string>,
  ): void {
    for (const member of group.members) {
      if (member.type !== "GROUP") continue;
      if (member.status === "ARCHIVED" || member.status === "SUSPENDED") {
        throw new Error(
          `Nested Google group ${normalizeEmail(member.email)} is ${member.status} in ${normalizeEmail(group.email)}`,
        );
      }
      const nestedEmail = normalizeEmail(member.email);
      if (queuedGroupKeys.has(nestedEmail)) continue;
      if (queuedGroupKeys.size >= MAX_RECURSIVE_GROUPS) {
        throw new Error(
          `Google group expansion exceeded ${String(MAX_RECURSIVE_GROUPS)} groups`,
        );
      }
      queuedGroupKeys.add(nestedEmail);
      pendingGroupKeys.push(nestedEmail);
    }
  }

  async #listMembers(
    groupId: string,
    token: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupMember[]> {
    const members: GoogleGroupMember[] = [];
    const seenPageTokens = new Set<string>();
    let pageToken = "";
    let page = 0;
    do {
      page++;
      if (page > MAX_MEMBER_PAGES) {
        throw new Error(
          `Google group ${groupId} exceeded ${String(MAX_MEMBER_PAGES)} pages`,
        );
      }
      if (pageToken && seenPageTokens.has(pageToken)) {
        throw new Error(
          `Google group ${groupId} returned a repeated page token`,
        );
      }
      if (pageToken) seenPageTokens.add(pageToken);
      const query = new URLSearchParams({ maxResults: "200" });
      if (pageToken) query.set("pageToken", pageToken);
      // eslint-disable-next-line no-await-in-loop -- Each members.list page token is returned by the preceding response.
      const response = await this.#requestDirectory(
        `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(groupId)}/members?${query.toString()}`,
        token,
        "google.directory.members.list",
        correlationId,
        deadlineAt,
      );
      // eslint-disable-next-line no-await-in-loop -- The current response body must be parsed before its next-page token is available.
      const parsed = GoogleGroupMembersPageSchema.parse(await response.json());
      members.push(...parsed.members);
      pageToken = parsed.nextPageToken ?? "";
    } while (pageToken);
    return members;
  }

  async #readGroup(
    groupKey: string,
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupIdentity> {
    const response = await this.#requestDirectory(
      `${DIRECTORY_GROUPS_ENDPOINT}/${encodeURIComponent(groupKey)}`,
      token,
      "google.directory.groups.get",
      runId,
      deadlineAt,
    );
    return GoogleGroupIdentitySchema.parse(await response.json());
  }

  async #requestDirectory(
    url: string,
    token: string,
    label: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<Response> {
    const response = await fetchWithRetry(
      url,
      {
        headers: {
          authorization: `Bearer ${token}`,
          "x-goog-user-project": this.#options.userProject,
        },
      },
      {
        ...(!(deadlineAt === undefined) && { deadlineAt }),
        fetchImpl: this.#options.fetchImpl,
        label,
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
    );
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(`${label} HTTP ${String(response.status)}`);
    }
    return response;
  }
}

function recordOwnerPageToken(
  groupId: string,
  pageToken: string,
  seen: Set<string>,
): void {
  if (!pageToken) return;
  if (seen.has(pageToken)) {
    throw new Error(
      `Google group ${groupId} owner listing returned a repeated page token`,
    );
  }
  seen.add(pageToken);
}

function addDirectOwners(
  owners: Set<string>,
  page: readonly GoogleGroupMember[],
): void {
  for (const owner of page) {
    if (owner.role !== "OWNER")
      throw new Error("Google owner-only listing returned a non-owner");
    if (owners.has(owner.id))
      throw new Error("Google owner-only listing returned a duplicate");
    owners.add(owner.id);
  }
}

function isContractorAuthorityEmail(email: string): boolean {
  const normalizedEmail = normalizeEmail(email);
  const authorityEmails: readonly string[] =
    contractorAuthorityGroup().acceptedEmails;
  return authorityEmails.includes(normalizedEmail);
}

async function readGroupBatches<Input, Output>(
  inputs: readonly Input[],
  read: (input: Input) => Promise<Output>,
): Promise<Output[]> {
  const values: Output[] = [];
  for (let index = 0; index < inputs.length; index += GROUP_READ_CONCURRENCY) {
    // eslint-disable-next-line no-await-in-loop -- Drain the entire bounded batch before another batch or a failure can escape.
    const results = await Promise.allSettled(
      inputs.slice(index, index + GROUP_READ_CONCURRENCY).map(read),
    );
    for (const result of results) {
      if (result.status === "rejected") {
        const failure: unknown = result.reason;
        throw failure instanceof Error
          ? failure
          : new Error("Google group snapshot read failed");
      }
      values.push(result.value);
    }
  }
  return values;
}
