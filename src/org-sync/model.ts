import {
  type GitHubLogin,
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import { isActiveGoogleUser } from "../google-workspace/user-lifecycle.ts";
import { normalizeIdentityEmail as normalizeEmail } from "../identity-sync/normalize-identity-email.ts";

export const ORG_SYNC_CRON = "7,22,37,52 * * * *";
export const ORG_SYNC_FIELD_LABELS = {
  linkedin: "LinkedIn",
  manages: "Manages",
  reportsTo: "Reports to",
  team: "Team",
} as const;
export const ORG_SYNC_DEPARTMENTS = [
  "Engineering",
  "Finance",
  "Marketing",
  "Operations",
  "People",
  "Product",
  "Sales",
] as const;
const ORG_SYNC_DEPARTMENT_SET: ReadonlySet<string> = new Set<string>(
  ORG_SYNC_DEPARTMENTS,
);

export interface GoogleOrganization {
  department?: string | undefined;
  primary?: boolean | undefined;
  title?: string | undefined;
}

export interface GoogleRelation {
  type?: string | undefined;
  value?: string | undefined;
}

export interface GoogleWebsite {
  customType?: string | undefined;
  primary?: boolean | undefined;
  type?: string | undefined;
  value?: string | undefined;
}

export interface GoogleDirectoryCustomSchemas {
  SarjIdentity?:
    | {
        githubLogin?: string | undefined;
        githubUserId?: string | undefined;
      }
    | undefined;
  SocialBot?:
    | {
        linkedinDigestPreferenceActionTs?: string | undefined;
        linkedinDigestOptOut?: boolean | undefined;
      }
    | undefined;
}

export interface GoogleDirectoryUser {
  aliases?: string[] | undefined;
  archived?: boolean | undefined;
  customSchemas?: GoogleDirectoryCustomSchemas | undefined;
  deletionTime?: string | undefined;
  etag?: string | undefined;
  id: string;
  isAdmin?: boolean | undefined;
  isDelegatedAdmin?: boolean | undefined;
  name?: { fullName?: string | undefined } | undefined;

  nonEditableAliases?: string[] | undefined;

  organizations?: GoogleOrganization[] | undefined;
  primaryEmail: string;

  relations?: GoogleRelation[] | undefined;
  suspended?: boolean | undefined;
  thumbnailPhotoUrl?: string | undefined;

  websites?: GoogleWebsite[] | undefined;
}

export interface GoogleDirectoryPreferenceUser {
  archived?: boolean | undefined;
  customSchemas?: GoogleDirectoryCustomSchemas | undefined;
  deletionTime?: string | undefined;
  etag?: string | undefined;
  id: string;
  suspended?: boolean | undefined;
}

export interface GoogleGitHubProfile {
  login: GitHubLogin;
  profileUrl: `https://github.com/${string}`;
}

export interface SlackProfileFieldValue {
  alt?: string | undefined;
  value?: string | undefined;
}

export interface SlackProfile {
  "display_name"?: string | undefined;
  email?: string | undefined;
  fields?: Record<string, SlackProfileFieldValue> | undefined;
  "real_name"?: string | undefined;
  title?: string | undefined;
}

export interface SlackMember {
  deleted?: boolean | undefined;
  "enterprise_user"?:
    | {
        "is_admin"?: boolean | undefined;
        "is_owner"?: boolean | undefined;
        "is_primary_owner"?: boolean | undefined;
      }
    | undefined;
  id: string;
  "is_admin"?: boolean | undefined;
  "is_app_user"?: boolean | undefined;
  "is_bot"?: boolean | undefined;
  "is_owner"?: boolean | undefined;
  "is_primary_owner"?: boolean | undefined;
  "is_restricted"?: boolean | undefined;
  "is_ultra_restricted"?: boolean | undefined;
  profile: SlackProfile;
  "team_id"?: string | undefined;
}

export interface ManagedFieldIds {
  linkedin: null | string;
  manages: string;
  reportsTo: string;
  team: string;
}

export interface DesiredManagedFields {
  linkedin: string;
  manages: string;
  reportsTo: string;
  team: string;
  title: string;
}

const MANAGED_FIELD_NAMES = [
  "reportsTo",
  "manages",
  "team",
  "linkedin",
  "title",
] as const;
export type ManagedFieldName = (typeof MANAGED_FIELD_NAMES)[number];

export interface ProfilePlan {
  changedFields: ManagedFieldName[];
  current: DesiredManagedFields;
  desired: DesiredManagedFields;
  googleUserId: null | string;
  identity: string;
  reason: "matched" | "not_org_participant" | "slack_orphan" | "suspended";
  slackUserId: string;
}

export interface OrgProjectionPlan {
  errors: string[];
  googleOnly: string[];
  googleParticipants: number;
  matched: number;
  participantDepartments: { department: string; userId: string }[];
  profiles: ProfilePlan[];
  rootGoogleUserIds: string[];
  slackOrphans: string[];
  unplacedGoogle: string[];
  warnings: string[];
}

export function canonicalSlackIds(value: string): string {
  return [
    ...new Set(
      value
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean),
    ),
  ]
    .toSorted(
      (sortLeft, sortRight) =>
        Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
    )
    .join(",");
}

export function readManagedFields(
  profile: SlackProfile,
  fieldIds: ManagedFieldIds,
): DesiredManagedFields {
  return {
    linkedin: fieldIds.linkedin
      ? fieldValue(profile, fieldIds.linkedin, "linkedin")
      : "",
    manages: fieldValue(profile, fieldIds.manages, "manages"),
    reportsTo: fieldValue(profile, fieldIds.reportsTo, "reportsTo"),
    team: fieldValue(profile, fieldIds.team, "team"),
    title: profile.title?.trim() ?? "",
  };
}

export function changedManagedFields(
  current: DesiredManagedFields,
  desired: DesiredManagedFields,
  fieldIds: ManagedFieldIds,
): ManagedFieldName[] {
  return MANAGED_FIELD_NAMES.filter(
    (name) =>
      (name !== "linkedin" || fieldIds.linkedin !== null) &&
      current[name] !== desired[name],
  );
}

export function buildOrgProjectionPlan(input: {
  excludedGoogleUserIds?: readonly string[];
  expectedRootGoogleUserIds?: readonly string[];
  fieldIds: ManagedFieldIds;
  googleUsers: GoogleDirectoryUser[];
  managedDomain: string;
  slackUsers: SlackMember[];
}): OrgProjectionPlan {
  const errors: string[] = [];
  const warnings: string[] = [];
  const excludedGoogleUserIds = new Set(input.excludedGoogleUserIds);
  const includedGoogleUsers = input.googleUsers.filter(
    (user) => !excludedGoogleUserIds.has(user.id),
  );
  const googleUsersById = new Map(
    includedGoogleUsers.map((user) => [user.id, user]),
  );
  if (
    new Set(input.googleUsers.map((user) => user.id)).size !==
    input.googleUsers.length
  ) {
    errors.push("Google Directory returned duplicate immutable user IDs");
  }
  const googleEmailIndex = buildGoogleEmailIndex(includedGoogleUsers, errors);
  const participants = buildParticipants(
    googleUsersById,
    googleEmailIndex,
    errors,
  );
  const slackEmailIndex = buildSlackEmailIndex(input.slackUsers, errors);
  const slackUserIds = new Set(input.slackUsers.map((user) => user.id));
  if (slackUserIds.size !== input.slackUsers.length) {
    errors.push("Slack returned duplicate immutable user IDs");
  }
  const slackByGoogleId = mapSlackUsersToGoogle(
    slackEmailIndex,
    googleEmailIndex,
    errors,
  );
  const unassigned = unassignedReportingManagers(
    participants,
    input.expectedRootGoogleUserIds,
    slackByGoogleId,
    warnings,
  );
  const reportsByManager = groupReportsByManager(participants);
  const unplacedGoogle = collectValues(googleUsersById.values())
    .filter(
      (user) =>
        isActiveGoogleDirectoryUser(user) &&
        primaryOrganization(user).kind === "none",
    )
    .map((user) => normalizeEmail(user.primaryEmail))
    .toSorted((a, b) => a.localeCompare(b));
  for (const identity of unplacedGoogle) {
    warnings.push(
      `Active Google identity has no primary organization: ${identity}`,
    );
  }

  const profiles: ProfilePlan[] = [];
  const slackOrphans: string[] = [];
  const domainSuffix = `@${input.managedDomain.toLocaleLowerCase("en-US")}`;
  const context: ProfileProjectionContext = {
    errors,
    googleEmailIndex,
    googleUsersById,
    participants,
    reportsByManager,
    slackByGoogleId,
    slackOrphans,
    ...unassigned,
    warnings,
  };
  for (const slackUser of input.slackUsers) {
    if (!activeSlackHuman(slackUser)) continue;
    const identity = normalizeEmail(slackUser.profile.email ?? "");
    if (!identity.endsWith(domainSuffix)) continue;
    profiles.push(projectSlackProfile(slackUser, input.fieldIds, context));
  }

  const googleOnly = collectValues(participants.values())
    .filter((participant) => !slackByGoogleId.has(participant.user.id))
    .map((participant) => participant.email)
    .toSorted((a, b) => a.localeCompare(b));
  for (const identity of googleOnly) {
    warnings.push(
      `Active Google org participant has no active Slack identity: ${identity}`,
    );
  }

  return {
    errors: [...new Set(errors)].toSorted((a, b) => a.localeCompare(b)),
    googleOnly,
    googleParticipants: participants.size,
    matched: profiles.filter((profile) => profile.reason === "matched").length,
    participantDepartments: collectValues(participants.values())
      .map((participant) => ({
        department: participant.department,
        userId: participant.user.id,
      }))
      .toSorted((a, b) => a.userId.localeCompare(b.userId)),
    profiles: profiles.toSorted((a, b) => a.identity.localeCompare(b.identity)),
    rootGoogleUserIds: collectValues(participants.values())
      .filter((participant) => participant.managerId === null)
      .map((participant) => participant.user.id)
      .toSorted((a, b) => a.localeCompare(b)),
    slackOrphans: slackOrphans.toSorted((a, b) => a.localeCompare(b)),
    unplacedGoogle,
    warnings: [...new Set(warnings)].toSorted((a, b) => a.localeCompare(b)),
  };
}

export function googleLinkedInUrl(user: GoogleDirectoryUser): null | string {
  if (!user.websites) return null;
  const linkedInValues = new Set<string>();
  for (const website of user.websites) {
    const explicitlyLinkedIn =
      website.type === "custom" &&
      website.customType?.trim().toLocaleLowerCase("en-US") === "linkedin";
    if (!explicitlyLinkedIn) continue;
    const value = website.value?.trim() ?? "";
    const normalized = value ? normalizeLinkedInUrl(value) : null;
    if (!normalized) {
      throw new Error(`Google user ${user.id} has an invalid LinkedIn website`);
    }
    linkedInValues.add(normalized);
  }
  if (linkedInValues.size > 1) {
    throw new Error(
      `Google user ${user.id} has more than one LinkedIn website`,
    );
  }
  return linkedInValues.values().next().value ?? null;
}

function collectValues<T>(values: Iterable<T>): T[] {
  const collected: T[] = [...values];
  return collected;
}

export function googleGitHubProfile(
  user: GoogleDirectoryUser,
): GoogleGitHubProfile | null {
  const identity = user.customSchemas?.SarjIdentity;
  if (!identity) return null;
  const login = GitHubLoginSchema.safeParse(identity.githubLogin);
  const userId = GitHubUserIdSchema.safeParse(identity.githubUserId);
  if (!login.success || !userId.success) {
    throw new Error(
      `Google user ${user.id} has an incomplete or invalid GitHub identity`,
    );
  }
  return {
    login: login.data,
    profileUrl: `https://github.com/${login.data}`,
  };
}

export function normalizeLinkedInUrl(value: string): null | string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  const hostname = parsed.hostname.toLocaleLowerCase("en-US");
  if (
    parsed.protocol !== "https:" ||
    (hostname !== "linkedin.com" && !hostname.endsWith(".linkedin.com"))
  ) {
    return null;
  }
  const match = /^\/in\/([^/?#]+)\/?$/u.exec(parsed.pathname);
  const slug = match?.[1]?.toLocaleLowerCase("en-US");
  return slug ? `https://www.linkedin.com/in/${slug}` : null;
}

interface GoogleParticipant {
  department: string;
  email: string;
  managerId: null | string;
  title: string;
  user: GoogleDirectoryUser;
}

export function isActiveGoogleDirectoryUser(
  user: GoogleDirectoryUser,
): boolean {
  return isActiveGoogleUser(user);
}

function activeSlackHuman(user: SlackMember): boolean {
  return (
    user.deleted !== true &&
    user["is_bot"] !== true &&
    user["is_app_user"] !== true
  );
}

type PrimaryOrganizationResult =
  | { kind: "multiple" }
  | { kind: "none" }
  | { kind: "one"; organization: GoogleOrganization };

function primaryOrganization(
  user: GoogleDirectoryUser,
): PrimaryOrganizationResult {
  const primary = (user.organizations ?? []).filter(
    (candidate) => candidate.primary === true,
  );
  if (primary.length === 0) return { kind: "none" };
  if (primary.length > 1) return { kind: "multiple" };
  const organization = primary[0];
  if (!organization) return { kind: "none" };
  return { kind: "one", organization };
}

function fieldValue(
  profile: SlackProfile,
  fieldId: string,
  field: ManagedFieldName,
): string {
  const raw = profile.fields?.[fieldId]?.value?.trim() ?? "";
  return field === "manages" ? canonicalSlackIds(raw) : raw;
}

function buildGoogleEmailIndex(
  users: GoogleDirectoryUser[],
  errors: string[],
): Map<string, string> {
  const index = new Map<string, string>();
  for (const user of users) {
    const addresses = [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ];
    for (const address of addresses) {
      const email = normalizeEmail(address);
      const existing = index.get(email);
      if (existing && existing !== user.id) {
        errors.push(`Google email or alias is ambiguous: ${email}`);
      } else {
        index.set(email, user.id);
      }
    }
  }
  return index;
}

function managerEmail(
  user: GoogleDirectoryUser,
  errors: string[],
): null | string {
  const managers = (user.relations ?? []).filter(
    (relation) => relation.type === "manager",
  );
  if (managers.length > 1) {
    errors.push(`Google user ${user.id} has more than one manager relation`);
    return null;
  }
  const value = managers[0]?.value?.trim();
  return value ? normalizeEmail(value) : null;
}

function buildParticipants(
  usersById: Map<string, GoogleDirectoryUser>,
  emailIndex: Map<string, string>,
  errors: string[],
): Map<string, GoogleParticipant> {
  const participants = new Map<string, GoogleParticipant>();
  for (const user of usersById.values()) {
    if (!isActiveGoogleDirectoryUser(user)) continue;
    const primary = primaryOrganization(user);
    if (primary.kind === "multiple") {
      errors.push(
        `Google user ${user.id} has more than one primary organization`,
      );
      continue;
    }
    if (primary.kind === "none") continue;
    const { organization } = primary;
    const department = participantDepartment(user, organization, errors);
    const manager = managerEmail(user, errors);
    const managerId = manager
      ? resolvedActiveManagerId(user, manager, usersById, emailIndex, errors)
      : null;
    participants.set(user.id, {
      department,
      email: normalizeEmail(user.primaryEmail),
      managerId,
      title: organization.title?.trim() ?? "",
      user,
    });
  }

  validateParticipantManagers(participants, usersById, errors);
  validateNoCycles(participants, errors);
  return participants;
}

function participantDepartment(
  user: GoogleDirectoryUser,
  organization: GoogleOrganization,
  errors: string[],
): string {
  const department = organization.department?.trim() ?? "";
  if (department && !ORG_SYNC_DEPARTMENT_SET.has(department)) {
    errors.push(
      `Google user ${user.id} has an unapproved department: ${department}`,
    );
  }
  return department;
}

function validateNoCycles(
  participants: Map<string, GoogleParticipant>,
  errors: string[],
): void {
  const completed = new Set<string>();
  for (const start of participants.keys()) {
    const path = new Set<string>();
    let cursor: null | string = start;
    while (cursor && !completed.has(cursor)) {
      if (path.has(cursor)) {
        errors.push(
          `Google reporting graph contains a cycle involving ${cursor}`,
        );
        break;
      }
      path.add(cursor);
      cursor = participants.get(cursor)?.managerId ?? null;
    }
    for (const id of path) completed.add(id);
  }
}

function resolvedActiveManagerId(
  user: GoogleDirectoryUser,
  initialManagerEmail: string,
  usersById: ReadonlyMap<string, GoogleDirectoryUser>,
  emailIndex: ReadonlyMap<string, string>,
  errors: string[],
): null | string {
  const visited = new Set([user.id]);
  let managerEmailValue: null | string = initialManagerEmail;
  while (managerEmailValue) {
    const managerId = emailIndex.get(managerEmailValue);
    if (!managerId) {
      errors.push(
        `Google manager for ${user.id} cannot be resolved: ${managerEmailValue}`,
      );
      return null;
    }
    if (visited.has(managerId)) {
      errors.push(
        `Google reporting graph contains a cycle involving ${managerId}`,
      );
      return null;
    }
    visited.add(managerId);
    const manager = usersById.get(managerId);
    if (!manager) {
      errors.push(
        `Google manager for ${user.id} cannot be resolved: ${managerEmailValue}`,
      );
      return null;
    }
    if (isActiveGoogleDirectoryUser(manager)) return managerId;
    managerEmailValue = managerEmail(manager, errors);
  }
  errors.push(
    `Google manager for ${user.id} has no active manager in its reporting chain`,
  );
  return null;
}

function validateParticipantManagers(
  participants: Map<string, GoogleParticipant>,
  usersById: Map<string, GoogleDirectoryUser>,
  errors: string[],
): void {
  for (const participant of participants.values()) {
    if (!participant.managerId) continue;
    const manager = usersById.get(participant.managerId);
    if (
      !manager ||
      !isActiveGoogleDirectoryUser(manager) ||
      !participants.has(participant.managerId)
    ) {
      errors.push(
        `Google manager for ${participant.user.id} is not an active org participant`,
      );
    } else if (participant.managerId === participant.user.id) {
      errors.push(`Google user ${participant.user.id} reports to itself`);
    }
  }
}

function buildSlackEmailIndex(
  users: SlackMember[],
  errors: string[],
): Map<string, SlackMember> {
  const index = new Map<string, SlackMember>();
  for (const user of users) {
    if (!activeSlackHuman(user)) continue;
    const emailValue = user.profile.email;
    if (!emailValue) continue;
    const email = normalizeEmail(emailValue);
    const existing = index.get(email);
    if (existing && existing.id !== user.id) {
      errors.push(`Slack email is ambiguous: ${email}`);
    } else {
      index.set(email, user);
    }
  }
  return index;
}

function mapSlackUsersToGoogle(
  slackEmailIndex: Map<string, SlackMember>,
  googleEmailIndex: Map<string, string>,
  errors: string[],
): Map<string, SlackMember> {
  const slackByGoogleId = new Map<string, SlackMember>();
  for (const slackUser of slackEmailIndex.values()) {
    const email = normalizeEmail(slackUser.profile.email ?? "");
    const googleId = googleEmailIndex.get(email);
    if (!googleId) continue;
    const existing = slackByGoogleId.get(googleId);
    if (existing && existing.id !== slackUser.id) {
      errors.push(`Multiple Slack users map to Google user ${googleId}`);
    } else {
      slackByGoogleId.set(googleId, slackUser);
    }
  }
  return slackByGoogleId;
}

function groupReportsByManager(
  participants: Map<string, GoogleParticipant>,
): Map<string, GoogleParticipant[]> {
  const reportsByManager = new Map<string, GoogleParticipant[]>();
  for (const participant of participants.values()) {
    if (!participant.managerId) continue;
    const reports = reportsByManager.get(participant.managerId) ?? [];
    reports.push(participant);
    reportsByManager.set(participant.managerId, reports);
  }
  return reportsByManager;
}

interface ProfileProjectionContext {
  errors: string[];
  googleEmailIndex: Map<string, string>;
  googleUsersById: Map<string, GoogleDirectoryUser>;
  participants: Map<string, GoogleParticipant>;
  reportsByManager: Map<string, GoogleParticipant[]>;
  slackByGoogleId: Map<string, SlackMember>;
  slackOrphans: string[];
  unassignedManagers: ReadonlySet<string>;
  unassignedSlackIds: ReadonlySet<string>;
  warnings: string[];
}

function unassignedReportingManagers(
  participants: ReadonlyMap<string, GoogleParticipant>,
  expectedRootGoogleUserIds: readonly string[] | undefined,
  slackByGoogleId: ReadonlyMap<string, SlackMember>,
  warnings: string[],
) {
  const unassignedManagers = new Set<string>();
  const unassignedSlackIds = new Set<string>();
  if (expectedRootGoogleUserIds === undefined)
    return { unassignedManagers, unassignedSlackIds };
  const expectedRoots = new Set(expectedRootGoogleUserIds);
  for (const participant of participants.values()) {
    if (
      participant.managerId !== null ||
      expectedRoots.has(participant.user.id)
    )
      continue;
    unassignedManagers.add(participant.user.id);
    const slackId = slackByGoogleId.get(participant.user.id)?.id;
    if (slackId) unassignedSlackIds.add(slackId);
    warnings.push(
      `Active Google org participant has no assigned manager: ${participant.email}`,
    );
  }
  return { unassignedManagers, unassignedSlackIds };
}

function projectSlackProfile(
  slackUser: SlackMember,
  fieldIds: ManagedFieldIds,
  context: ProfileProjectionContext,
): ProfilePlan {
  const identity = normalizeEmail(slackUser.profile.email ?? "");
  const googleId = context.googleEmailIndex.get(identity);
  const googleUser = googleId
    ? context.googleUsersById.get(googleId)
    : undefined;
  const participant = googleId ? context.participants.get(googleId) : undefined;
  const currentTitle = slackUser.profile.title?.trim() ?? "";
  let desired = emptyDesired(currentTitle);
  let reason: ProfilePlan["reason"] = "slack_orphan";

  if (!googleUser) {
    context.slackOrphans.push(identity);
    context.warnings.push(
      `Active internal Slack user has no Google identity: ${identity}`,
    );
  } else if (!isActiveGoogleDirectoryUser(googleUser)) {
    reason = "suspended";
    context.warnings.push(
      `Active Slack user maps to inactive Google user: ${identity}`,
    );
  } else if (!participant) {
    reason = "not_org_participant";
    context.warnings.push(
      `Active Slack user has no primary Google organization and projects empty org fields: ${identity}`,
    );
  } else {
    reason = "matched";
    desired = desiredForParticipant(
      participant,
      identity,
      context,
      currentTitle,
    );
  }

  const current = currentFields(slackUser, fieldIds);
  if (participant) {
    if (context.unassignedManagers.has(participant.user.id)) {
      desired.reportsTo = current.reportsTo;
    }
    // Missing Directory relations are incomplete evidence. Retain existing inverse
    // links until a manager is assigned instead of silently erasing them.
    const retainedReports = current.manages
      .split(",")
      .filter((id) => context.unassignedSlackIds.has(id));
    desired.manages = canonicalSlackIds(
      [desired.manages, ...retainedReports].join(","),
    );
  }
  if (fieldIds.linkedin === null) desired.linkedin = current.linkedin;
  return {
    changedFields: changedManagedFields(current, desired, fieldIds),
    current,
    desired,
    googleUserId: googleId ?? null,
    identity,
    reason,
    slackUserId: slackUser.id,
  };
}

function desiredForParticipant(
  participant: GoogleParticipant,
  identity: string,
  context: ProfileProjectionContext,
  currentTitle: string,
): DesiredManagedFields {
  const managerSlack = participant.managerId
    ? context.slackByGoogleId.get(participant.managerId)
    : undefined;
  if (participant.managerId && !managerSlack) {
    context.errors.push(
      `Google manager is not active in Slack for ${identity}`,
    );
  }
  const reports = (context.reportsByManager.get(participant.user.id) ?? [])
    .map((report) => ({
      report,
      slack: context.slackByGoogleId.get(report.user.id),
    }))
    .filter(
      (entry): entry is { report: GoogleParticipant; slack: SlackMember } =>
        entry.slack !== undefined && activeSlackHuman(entry.slack),
    )
    .toSorted((a, b) => a.report.email.localeCompare(b.report.email));
  if (reports.length > 25) {
    context.errors.push(
      `Google manager ${participant.user.id} has more than 25 Slack-present reports`,
    );
  }
  return {
    linkedin: googleLinkedInUrl(participant.user) ?? "",
    manages: canonicalSlackIds(
      reports.map((entry) => entry.slack.id).join(","),
    ),
    reportsTo: managerSlack?.id ?? "",
    team: participant.department,
    title: participant.title || currentTitle,
  };
}

function emptyDesired(currentTitle: string): DesiredManagedFields {
  return {
    linkedin: "",
    manages: "",
    reportsTo: "",
    team: "",
    title: currentTitle,
  };
}

function currentFields(
  user: SlackMember,
  fieldIds: ManagedFieldIds,
): DesiredManagedFields {
  return readManagedFields(user.profile, fieldIds);
}
