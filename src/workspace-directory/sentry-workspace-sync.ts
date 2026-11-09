import { dequal } from "dequal";
import { z } from "zod";

import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  type ISentryWorkspaceClient,
  type SentryWorkspaceSnapshot,
  sentryMemberEmail,
} from "./sentry-workspace-client.ts";

const EmailSchema = z.email().toLowerCase();
const MAX_AUTHORITY_MEMBERS = 50;
const MAX_ACTIONS = 25;

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

export const SentryWorkspaceActionSchema = z.discriminatedUnion("type", [
  z.strictObject({
    email: EmailSchema,
    memberId: z.string().regex(/^\d{1,32}$/u),
    type: z.literal("remove-organization-member"),
  }),
  z.strictObject({
    email: EmailSchema,
    memberId: z.string().min(1),
    type: z.literal("add-team-member"),
  }),
  z.strictObject({ email: EmailSchema, type: z.literal("invite") }),
  z.strictObject({
    email: EmailSchema,
    memberId: z.string().min(1),
    type: z.literal("repair-pending-invite"),
  }),
  z.strictObject({
    email: EmailSchema,
    memberId: z.string().min(1),
    type: z.literal("reinvite-expired"),
  }),
]);
export type SentryWorkspaceAction = z.output<
  typeof SentryWorkspaceActionSchema
>;

export interface SentryWorkspacePlan {
  readonly actions: readonly SentryWorkspaceAction[];
  readonly activeGoogleMembers: readonly string[];
}

export const AuditedSentryWorkspacePlanSchema = z.strictObject({
  actions: z.array(SentryWorkspaceActionSchema),
  activeGoogleMembers: z.array(EmailSchema),
  planHash: Sha256Schema,
});
export type AuditedSentryWorkspacePlan = z.output<
  typeof AuditedSentryWorkspacePlanSchema
>;

/*
 * Projects active Google team-platform identities onto Sentry. The policy is
 * deliberately additive: existing memberships and privileges are never removed
 * or downgraded, and a live pending invitation is never duplicated.
 */
export function planSentryWorkspaceSync(
  rawActiveGoogleMembers: readonly string[],
  snapshot: SentryWorkspaceSnapshot,
): SentryWorkspacePlan {
  if (rawActiveGoogleMembers.length > MAX_AUTHORITY_MEMBERS) {
    throw new SentryWorkspacePlanBoundError("authority");
  }
  const activeGoogleMembers = [
    ...new Set(rawActiveGoogleMembers.map((email) => EmailSchema.parse(email))),
  ].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  assertManagedTeamAttached(snapshot);
  const organizationByEmail = uniqueByEmail(
    snapshot.organizationMembers,
    "organization",
  );
  const teamEmails = new Set(nonNullEmails(snapshot.teamMembers));
  const actions: SentryWorkspaceAction[] = [];

  for (const email of activeGoogleMembers) {
    const action = actionForMember(
      email,
      organizationByEmail.get(email),
      teamEmails,
    );
    if (action !== null) actions.push(action);
  }
  if (actions.length > MAX_ACTIONS)
    throw new SentryWorkspacePlanBoundError("action");
  return {
    actions: SentryWorkspaceActionSchema.array().parse(actions),
    activeGoogleMembers,
  };
}

function actionForMember(
  email: string,
  member: SentryWorkspaceSnapshot["organizationMembers"][number] | undefined,
  teamEmails: ReadonlySet<string>,
): null | SentryWorkspaceAction {
  if (member === undefined) return { email, type: "invite" };
  if (!isOrdinarySentryMember(member)) return null;
  if (member.pending && member.expired) {
    return { email, memberId: member.id, type: "reinvite-expired" };
  }
  if (member.pending && !memberHasManagedTeam(member)) {
    return { email, memberId: member.id, type: "repair-pending-invite" };
  }
  if (!member.pending && !teamEmails.has(email)) {
    return { email, memberId: member.id, type: "add-team-member" };
  }
  return null;
}

function isOrdinarySentryMember(
  member: SentryWorkspaceSnapshot["organizationMembers"][number],
): boolean {
  const uniqueTeamSlugs = new Set(
    member.teamRoles.map(({ teamSlug }) => teamSlug),
  );
  return (
    member.orgRole === "member" &&
    member.role === "member" &&
    uniqueTeamSlugs.size === member.teamRoles.length &&
    member.teamRoles.every(({ role }) => role === "contributor")
  );
}

export async function auditSentryWorkspaceSync(
  activeGoogleMembers: readonly string[],
  client: ISentryWorkspaceClient,
): Promise<AuditedSentryWorkspacePlan> {
  const plan = planSentryWorkspaceSync(
    activeGoogleMembers,
    await client.snapshot(activeGoogleMembers),
  );
  return AuditedSentryWorkspacePlanSchema.parse({
    ...plan,
    planHash: Sha256Schema.parse(
      await contentHash({
        actions: plan.actions,
        activeGoogleMembers: plan.activeGoogleMembers,
        projectTeamSlug: getWorkspaceSyncPolicy().sentryTeamSlug,
      }),
    ),
  });
}

/* Proves the exact action target is already converged from a fresh provider snapshot. */
export async function isSentryWorkspaceActionConverged(
  client: ISentryWorkspaceClient,
  rawAction: SentryWorkspaceAction,
): Promise<boolean> {
  const action = SentryWorkspaceActionSchema.parse(rawAction);
  if (action.type === "remove-organization-member")
    throw new Error("sentry_removal_signed_parent_required");
  const current = await client.snapshot(memberDetailEmailsForAction(action));
  assertManagedTeamAttached(current);
  return isConverged(action, current);
}

/* Re-audits authority and provider state, then applies one action from the exact pinned plan. */
export async function applySentryWorkspacePlanAction(
  activeGoogleMembers: readonly string[],
  client: ISentryWorkspaceClient,
  rawAction: SentryWorkspaceAction,
  expectedPlanHash: string,
  assertWriteAuthority: () => Promise<void>,
  assertTransportAuthority?: () => Promise<void>,
): Promise<void> {
  const action = SentryWorkspaceActionSchema.parse(rawAction);
  const current = await auditSentryWorkspaceSync(activeGoogleMembers, client);
  if (
    current.planHash !== Sha256Schema.parse(expectedPlanHash) ||
    !current.actions.some((candidate) => sameAction(candidate, action))
  ) {
    throw new SentryWorkspaceDriftError();
  }
  await applySentryWorkspaceAction(
    client,
    action,
    assertWriteAuthority,
    assertTransportAuthority,
  );
}

/* Applies exactly one reviewed action and then verifies the provider's exact target slice. */
export async function applySentryWorkspaceAction(
  client: ISentryWorkspaceClient,
  rawAction: SentryWorkspaceAction,
  assertWriteAuthority: () => Promise<void>,
  assertTransportAuthority?: () => Promise<void>,
): Promise<void> {
  const action = SentryWorkspaceActionSchema.parse(rawAction);
  if (action.type === "remove-organization-member")
    throw new Error("sentry_removal_signed_parent_required");
  const memberDetailEmails = memberDetailEmailsForAction(action);
  const before = await client.snapshot(memberDetailEmails);
  assertManagedTeamAttached(before);
  if (isConverged(action, before)) return;
  assertStillSafe(action, before);
  await assertWriteAuthority();
  switch (action.type) {
    case "add-team-member":
      await client.addTeamMember(action.memberId, assertTransportAuthority);
      break;
    case "invite":
      await client.invite(action.email, assertTransportAuthority);
      break;
    case "reinvite-expired":
      await client.reinvite(action.memberId, assertTransportAuthority);
      break;
    case "repair-pending-invite":
      await client.addTeamMember(action.memberId, assertTransportAuthority);
      break;
  }

  const after = await client.snapshot(memberDetailEmails);
  if (!isConverged(action, after))
    throw new SentryWorkspaceReadbackError(action.type);
}

function isConverged(
  action: SentryWorkspaceAction,
  snapshot: SentryWorkspaceSnapshot,
): boolean {
  const organizationMember = snapshot.organizationMembers.find(
    (member) => sentryMemberEmail(member) === action.email,
  );
  if (action.type === "invite") {
    return (
      organizationMember?.pending === true &&
      !organizationMember.expired &&
      memberHasManagedTeam(organizationMember)
    );
  }
  if (action.type === "reinvite-expired") {
    return (
      organizationMember?.id === action.memberId &&
      organizationMember.pending &&
      !organizationMember.expired
    );
  }
  if (action.type === "repair-pending-invite") {
    return (
      organizationMember?.id === action.memberId &&
      organizationMember.pending &&
      !organizationMember.expired &&
      memberHasManagedTeam(organizationMember)
    );
  }
  return (
    organizationMember?.id === action.memberId &&
    !organizationMember.pending &&
    snapshot.teamMembers.some(
      (member) =>
        member.id === action.memberId &&
        sentryMemberEmail(member) === action.email,
    )
  );
}

function memberHasManagedTeam(
  member: SentryWorkspaceSnapshot["organizationMembers"][number],
): boolean {
  return (
    member.teams?.includes(getWorkspaceSyncPolicy().sentryTeamSlug) === true
  );
}

function memberDetailEmailsForAction(
  action: SentryWorkspaceAction,
): readonly string[] {
  return [action.email];
}

function assertManagedTeamAttached(snapshot: SentryWorkspaceSnapshot): void {
  if (
    !snapshot.projectTeams.some(
      ({ slug }) => slug === getWorkspaceSyncPolicy().sentryTeamSlug,
    )
  ) {
    throw new SentryWorkspaceProjectTeamError();
  }
}

function sameAction(
  left: SentryWorkspaceAction,
  right: SentryWorkspaceAction,
): boolean {
  return dequal(left, right);
}

function assertStillSafe(
  action: SentryWorkspaceAction,
  snapshot: SentryWorkspaceSnapshot,
): void {
  const member = snapshot.organizationMembers.find(
    (candidate) => sentryMemberEmail(candidate) === action.email,
  );
  if (action.type === "invite") {
    if (member !== undefined) throw new SentryWorkspaceDriftError();
    return;
  }
  if (member?.id !== action.memberId || !isOrdinarySentryMember(member))
    throw new SentryWorkspaceDriftError();
  if (action.type === "add-team-member" && member.pending)
    throw new SentryWorkspaceDriftError();
  if (
    action.type === "reinvite-expired" &&
    (!member.pending || !member.expired)
  ) {
    throw new SentryWorkspaceDriftError();
  }
  if (
    action.type === "repair-pending-invite" &&
    (!member.pending || member.expired)
  ) {
    throw new SentryWorkspaceDriftError();
  }
}

function uniqueByEmail(
  members: SentryWorkspaceSnapshot["organizationMembers"],
  source: string,
): Map<string, SentryWorkspaceSnapshot["organizationMembers"][number]> {
  const result = new Map<
    string,
    SentryWorkspaceSnapshot["organizationMembers"][number]
  >();
  for (const member of members) {
    const email = sentryMemberEmail(member);
    if (email === null) continue;
    if (result.has(email))
      throw new Error(`sentry_workspace_duplicate_${source}_identity`);
    result.set(email, member);
  }
  return result;
}

function nonNullEmails(
  members: SentryWorkspaceSnapshot["teamMembers"],
): string[] {
  return members
    .map(sentryMemberEmail)
    .filter((email): email is string => email !== null);
}

export class SentryWorkspacePlanBoundError extends Error {
  constructor(bound: "action" | "authority", options?: ErrorOptions) {
    super(`sentry_workspace_${bound}_bound_exceeded`, options);
    this.name = "SentryWorkspacePlanBoundError";
  }
}

export class SentryWorkspaceDriftError extends Error {
  constructor() {
    super("sentry_workspace_prewrite_drift");
    this.name = "SentryWorkspaceDriftError";
  }
}

export class SentryWorkspaceReadbackError extends Error {
  constructor(action: SentryWorkspaceAction["type"], options?: ErrorOptions) {
    super(`sentry_workspace_readback_failed:${action}`, options);
    this.name = "SentryWorkspaceReadbackError";
  }
}

export class SentryWorkspaceProjectTeamError extends Error {
  constructor() {
    super("sentry_workspace_managed_team_not_attached_to_project");
    this.name = "SentryWorkspaceProjectTeamError";
  }
}
