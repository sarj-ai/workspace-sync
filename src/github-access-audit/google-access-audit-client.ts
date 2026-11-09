import { z } from "zod";

import { normalizeIdentityEmail as normalize } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import { fetchWithRetry } from "../org-sync/http.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type { GoogleAuthoritySnapshot } from "./google-contracts.ts";

const REPORTS_SCOPE =
  "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const REPORTS_ENDPOINT =
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin";
const MEMBERSHIP_EVENT_NAMES: ReadonlySet<string> = new Set([
  "ADD_GROUP_MEMBER",
  "REMOVE_GROUP_MEMBER",
  "GROUP_MEMBER_ADD",
  "GROUP_MEMBER_DELETE",
  "GROUP_MEMBER_REMOVE",
]);
const ReportsPageSchema = z.object({
  items: z
    .array(
      z.object({
        events: z
          .array(
            z.object({
              name: z.string().min(1),
              parameters: z
                .array(
                  z.object({
                    multiValue: z.array(z.string()).optional(),
                    name: z.string().min(1),
                    value: z
                      .union([z.string(), z.number(), z.boolean()])
                      .optional(),
                  }),
                )
                .default([]),
            }),
          )
          .default([]),
        id: z.object({ time: z.string().min(1) }),
      }),
    )
    .default([]),
  nextPageToken: z.string().optional(),
});

interface GroupReadFailed {
  kind: "failed";
}
interface GroupReadFound {
  group: GoogleGroupSnapshot;
  kind: "found";
}
type GroupReadResult = GroupReadFailed | GroupReadFound;

export interface GoogleAccessAuditClientDependencies {
  directory: {
    listAllUsers(
      runId: string,
      deadlineAt?: number,
    ): Promise<GoogleDirectoryUser[]>;
    listDeletedUsers(
      runId: string,
      deadlineAt?: number,
    ): Promise<GoogleDirectoryUser[]>;
  };
  fetchImpl?: typeof fetch;
  groups: {
    listGroups(
      groupKeys: readonly string[],
      runId: string,
      deadlineAt?: number,
    ): Promise<GoogleGroupSnapshot[]>;
  };
  reportsAuth: {
    accessToken(
      scope: string,
      runId: string,
      deadlineAt?: number,
    ): Promise<string>;
  };
  userProject: string;
}

export interface GoogleAccessAuditRequest {
  mappedGroupEmails: readonly string[];
  reportsLookbackDays?: number;
  rootGroupEmail: string;
}

export interface IGoogleAccessAuditClient {
  capture(
    request: GoogleAccessAuditRequest,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleAuthoritySnapshot>;
}

/** Builds a fresh authority graph entirely from bounded, read-only Directory API calls. */
export class GoogleAccessAuditClient implements IGoogleAccessAuditClient {
  readonly #directory: GoogleAccessAuditClientDependencies["directory"];
  readonly #fetchImpl: typeof fetch | undefined;
  readonly #groups: GoogleAccessAuditClientDependencies["groups"];
  readonly #reportsAuth: GoogleAccessAuditClientDependencies["reportsAuth"];
  readonly #userProject: string;

  constructor(dependencies: GoogleAccessAuditClientDependencies) {
    this.#directory = dependencies.directory;
    this.#fetchImpl = dependencies.fetchImpl;
    this.#groups = dependencies.groups;
    this.#reportsAuth = dependencies.reportsAuth;
    this.#userProject = dependencies.userProject;
  }

  async capture(
    request: GoogleAccessAuditRequest,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleAuthoritySnapshot> {
    const issues: GoogleAuthoritySnapshot["issues"] = [];
    try {
      const [users, deletedUsers] = await Promise.all([
        this.#directory.listAllUsers(runId, deadlineAt),
        this.#directory.listDeletedUsers(runId, deadlineAt),
      ]);
      const normalizedUsers = [
        ...normalizeUsers(users, false),
        ...normalizeUsers(deletedUsers, true),
      ];
      const identityCollisionIssues =
        googleIdentityCollisionIssues(normalizedUsers);
      issues.push(...identityCollisionIssues);
      const { allGroups, groupTraversalComplete } = await this.#collectGroups(
        request,
        runId,
        issues,
        deadlineAt,
      );
      const groups = allGroups.map((group) => ({
        email: group.email,
        id: group.id,
      }));
      const memberships = allGroups.flatMap((group) =>
        group.members
          .filter((member) => member.type !== "CUSTOMER")
          .map((member) => ({
            groupId: group.id,
            memberEmail: member.email,
            memberId: member.id,
            memberType: member.type,
            role: member.role,
            status: member.status,
          })),
      );
      const root = groups.find(
        (group) => normalize(group.email) === normalize(request.rootGroupEmail),
      );
      if (!root) {
        return {
          capturedAt: new Date().toISOString(),
          complete: false,
          groups,
          issues: [
            ...issues,
            { code: "root_group_missing", message: request.rootGroupEmail },
          ],
          memberships,
          reachableGroupIds: [],
          reports: {
            events: [],
            issues: ["Root group missing"],
            status: "unavailable",
          },
          unmappedDescendantGroups: [],
          users: normalizedUsers,
        };
      }
      const reachableGroupIds = reachableGroups(root.id, memberships);
      const mapped = new Set(request.mappedGroupEmails.map(normalize));
      const unmappedDescendantGroups = groups.filter(
        (group) =>
          group.id !== root.id &&
          reachableGroupIds.includes(group.id) &&
          !mapped.has(normalize(group.email)),
      );
      const reports = await this.#readReports(
        runId,
        request.reportsLookbackDays ?? 45,
        deadlineAt,
      );
      return {
        capturedAt: new Date().toISOString(),
        complete:
          groupTraversalComplete && identityCollisionIssues.length === 0,
        groups,
        issues,
        memberships,
        reachableGroupIds,
        reports,
        unmappedDescendantGroups,
        users: normalizedUsers,
      };
    } catch (error) {
      issues.push({
        code: "directory_snapshot_failed",
        message: error instanceof Error ? error.message : String(error),
      });
      return {
        capturedAt: new Date().toISOString(),
        complete: false,
        groups: [],
        issues,
        memberships: [],
        reachableGroupIds: [],
        reports: {
          events: [],
          issues: ["Directory snapshot failed"],
          status: "unavailable",
        },
        unmappedDescendantGroups: [],
        users: [],
      };
    }
  }

  async #collectGroups(
    request: GoogleAccessAuditRequest,
    runId: string,
    issues: GoogleAuthoritySnapshot["issues"],
    deadlineAt?: number,
  ): Promise<{
    allGroups: GoogleGroupSnapshot[];
    groupTraversalComplete: boolean;
  }> {
    const pending = [request.rootGroupEmail, ...request.mappedGroupEmails];
    const allGroups: GoogleGroupSnapshot[] = [];
    const seenEmails = new Set<string>();
    let groupTraversalComplete = true;
    while (pending.length > 0) {
      const email = pending.shift();
      if (!email || seenEmails.has(normalize(email))) continue;
      if (seenEmails.size >= 100)
        throw new Error("Google group traversal exceeded 100 groups");
      seenEmails.add(normalize(email));
      // eslint-disable-next-line no-await-in-loop -- Each group failure is isolated so the audit preserves partial evidence.
      const groupRead = await this.#readGroup(email, runId, issues, deadlineAt);
      if (groupRead.kind === "failed") {
        groupTraversalComplete = false;
        continue;
      }
      const { group } = groupRead;
      allGroups.push(group);
      for (const member of group.members) {
        if (
          member.type === "GROUP" &&
          !seenEmails.has(normalize(member.email))
        ) {
          pending.push(member.email);
        }
      }
    }
    return { allGroups, groupTraversalComplete };
  }

  async #readGroup(
    email: string,
    runId: string,
    issues: GoogleAuthoritySnapshot["issues"],
    deadlineAt?: number,
  ): Promise<GroupReadResult> {
    let group: GoogleGroupSnapshot | undefined;
    try {
      [group] = await this.#groups.listGroups([email], runId, deadlineAt);
    } catch (error) {
      issues.push({
        code: "group_read_failed",
        message: `${email}: ${error instanceof Error ? error.message : String(error)}`,
      });
      return { kind: "failed" };
    }
    if (!group) throw new Error(`Google group ${email} returned no snapshot`);
    return { group, kind: "found" };
  }

  async #readReports(
    runId: string,
    lookbackDays: number,
    deadlineAt?: number,
  ): Promise<NonNullable<GoogleAuthoritySnapshot["reports"]>> {
    try {
      const token = await this.#reportsAuth.accessToken(
        REPORTS_SCOPE,
        runId,
        deadlineAt,
      );
      const events: NonNullable<GoogleAuthoritySnapshot["reports"]>["events"] =
        [];
      let pageToken = "";
      const seen = new Set<string>();
      for (let page = 1; page <= 10; page++) {
        const start = new Date(
          Date.now() - lookbackDays * 24 * 60 * 60 * 1000,
        ).toISOString();
        const query = new URLSearchParams({
          maxResults: "1000",
          startTime: start,
        });
        if (pageToken) query.set("pageToken", pageToken);
        // eslint-disable-next-line no-await-in-loop -- Reports pagination is ordered and capped.
        const response = await fetchWithRetry(
          `${REPORTS_ENDPOINT}?${query.toString()}`,
          {
            headers: {
              authorization: `Bearer ${token}`,
              "x-goog-user-project": this.#userProject,
            },
          },
          {
            ...(!(deadlineAt === undefined) && { deadlineAt }),
            fetchImpl: this.#fetchImpl,
            label: "google.reports.admin_activity.list",
            runId,
          },
        );
        if (!response.ok) {
          // eslint-disable-next-line no-await-in-loop -- Cancel the current paginated response before returning partial data.
          await response.body?.cancel();
          return {
            events,
            issues: [`Google Reports HTTP ${String(response.status)}`],
            status: events.length > 0 ? "partial" : "unavailable",
          };
        }
        // eslint-disable-next-line no-await-in-loop -- Parse follows the bounded request above.
        const parsed = ReportsPageSchema.parse(await response.json());
        events.push(...membershipEvents(parsed));
        pageToken = parsed.nextPageToken ?? "";
        if (!pageToken) return { events, status: "available" };
        if (seen.has(pageToken)) {
          return {
            events,
            issues: ["Repeated Google Reports page token"],
            status: "partial",
          };
        }
        seen.add(pageToken);
      }
      return {
        events,
        issues: ["Google Reports page limit exceeded"],
        status: "partial",
      };
    } catch (error) {
      return unavailableReports(error);
    }
  }
}

function unavailableReports(
  error: unknown,
): NonNullable<GoogleAuthoritySnapshot["reports"]> {
  if (error instanceof z.ZodError) throw error;
  const message = error instanceof Error ? error.message : String(error);
  if (
    message.includes("deadline exceeded") ||
    message.includes("network failure")
  )
    throw error;
  return { events: [], issues: [message], status: "unavailable" };
}

function membershipEvents(
  page: z.infer<typeof ReportsPageSchema>,
): NonNullable<GoogleAuthoritySnapshot["reports"]>["events"] {
  return page.items.flatMap((activity) =>
    activity.events.flatMap((event) => {
      if (!MEMBERSHIP_EVENT_NAMES.has(event.name.toUpperCase())) return [];
      const groupEmail = reportParameter(event.parameters, [
        "GROUP_EMAIL",
        "GROUP_ID",
        "GROUP_NAME",
      ]);
      const subjectEmail = reportParameter(event.parameters, [
        "MEMBER_EMAIL",
        "USER_EMAIL",
        "USER_ID",
      ]);
      return {
        ...(!(groupEmail === undefined) && { groupEmail }),
        name: event.name,
        parameters: Object.fromEntries(
          event.parameters.map((parameter) => [
            parameter.name,
            parameter.multiValue ??
              (parameter.value === undefined ? [] : [String(parameter.value)]),
          ]),
        ),
        ...(!(subjectEmail === undefined) && { subjectEmail }),
        time: activity.id.time,
      };
    }),
  );
}

function reportParameter(
  parameters: {
    multiValue?: string[] | undefined;
    name: string;
    value?: boolean | number | string | undefined;
  }[],
  names: readonly string[],
): string | undefined {
  const parameter = parameters.find((candidate) =>
    names.includes(candidate.name.toUpperCase()),
  );
  const value = parameter?.multiValue?.[0] ?? parameter?.value;
  return value === undefined ? undefined : normalize(String(value));
}

function reachableGroups(
  rootId: string,
  memberships: GoogleAuthoritySnapshot["memberships"],
): string[] {
  const reachable = new Set<string>();
  const pending = [rootId];
  while (pending.length > 0) {
    const groupId = pending.pop();
    if (!groupId || reachable.has(groupId)) continue;
    reachable.add(groupId);
    for (const member of memberships) {
      if (member.groupId === groupId && member.memberType === "GROUP")
        pending.push(member.memberId);
    }
  }
  return [...reachable].toSorted(compareString);
}

function normalizeUsers(
  users: GoogleDirectoryUser[],
  deleted: boolean,
): GoogleAuthoritySnapshot["users"] {
  return users.map((user) => ({
    aliases: [
      ...new Set(
        [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])].map(
          normalize,
        ),
      ),
    ].toSorted(compareString),
    archived: user.archived === true,
    deleted,
    id: user.id,
    primaryEmail: normalize(user.primaryEmail),
    suspended: user.suspended === true,
  }));
}

function googleIdentityCollisionIssues(
  users: GoogleAuthoritySnapshot["users"],
): GoogleAuthoritySnapshot["issues"] {
  const idsByAddress = new Map<string, Set<string>>();
  for (const user of users) {
    for (const address of [user.primaryEmail, ...user.aliases]) {
      const ids = idsByAddress.get(address) ?? new Set<string>();
      ids.add(user.id);
      idsByAddress.set(address, ids);
    }
  }
  return [...idsByAddress]
    .filter(([, ids]) => ids.size > 1)
    .map(([address]) => ({
      code: "google_identity_collision",
      message: `Multiple immutable Google user IDs claim ${address}`,
    }));
}

function compareString(left: string, right: string): number {
  return left.localeCompare(right);
}
