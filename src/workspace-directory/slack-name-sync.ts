import { dequal } from "dequal";
import { z } from "zod";

import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type {
  GoogleDirectoryUser,
  SlackMember,
  SlackProfile,
} from "../org-sync/model.ts";
import type {
  IOrgSlackClient,
  SlackSnapshot,
} from "../org-sync/org-slack-client.ts";
import { indexNamedActiveGoogleUsers } from "./index-named-active-google-users.ts";

const MAX_ACTIONS = 100;
const MAX_GOOGLE_USERS = 500;
const REQUIRED_SLACK_SCOPES = [
  "users.profile:write",
  "users:read",
  "users:read.email",
] as const;
const EmailSchema = z.email().toLowerCase();
const NameSchema = z.string().trim().min(1).max(50);
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
export const SlackNameActionSchema = z.strictObject({
  beforeRealName: z.string().max(50),
  desiredName: NameSchema,
  email: EmailSchema,
  googleUserId: z.string().min(1),
  slackUserId: z.string().min(1),
  type: z.literal("repair-default-name"),
});
export type SlackNameAction = z.output<typeof SlackNameActionSchema>;

export const AuditedSlackNamePlanSchema = z.strictObject({
  actions: z.array(SlackNameActionSchema),
  actorUserId: z.string().min(1),
  authorityUsers: z.array(
    z.strictObject({
      email: EmailSchema,
      googleUserId: z.string().min(1),
      name: NameSchema,
    }),
  ),
  planHash: Sha256Schema,
  teamId: z.string().min(1),
});
export type AuditedSlackNamePlan = z.output<typeof AuditedSlackNamePlanSchema>;

export type ISlackNameClient = Pick<
  IOrgSlackClient,
  "getProfile" | "listSnapshot" | "setProfile"
>;

export async function auditSlackNameSync(
  googleUsers: readonly GoogleDirectoryUser[],
  slack: ISlackNameClient,
  expectedTeamId: string,
): Promise<AuditedSlackNamePlan> {
  const runId = crypto.randomUUID();
  const snapshot = await slack.listSnapshot(runId);
  return auditSlackNameSnapshot(googleUsers, snapshot, expectedTeamId);
}

async function auditSlackNameSnapshot(
  googleUsers: readonly GoogleDirectoryUser[],
  snapshot: SlackSnapshot,
  expectedTeamId: string,
): Promise<AuditedSlackNamePlan> {
  if (snapshot.teamId !== expectedTeamId)
    throw new SlackNameIdentityError("workspace");
  const plan = planSlackNameSync(googleUsers, snapshot);
  return AuditedSlackNamePlanSchema.parse({
    ...plan,
    planHash: await contentHash({
      ...plan,
      policy: "google-full-name-to-slack-email-default-real-name-v2",
    }),
  });
}

export function planSlackNameSync(
  googleUsers: readonly GoogleDirectoryUser[],
  snapshot: SlackSnapshot,
): Omit<AuditedSlackNamePlan, "planHash"> {
  if (googleUsers.length > MAX_GOOGLE_USERS)
    throw new SlackNameBoundError("authority");
  if (REQUIRED_SLACK_SCOPES.some((scope) => !snapshot.scopes.includes(scope))) {
    throw new SlackNameIdentityError("scope");
  }
  const googleByEmail = indexNamedActiveGoogleUsers(
    googleUsers,
    () => new SlackNameIdentityError("google"),
  );
  const authorityUsers = new Map(
    googleByEmail.values().map((user) => [user.id, user] as const),
  )
    .values()
    .map((user) => {
      const name = NameSchema.safeParse(user.name?.fullName);
      return name.success
        ? {
            email: normalizeIdentityEmail(user.primaryEmail),
            googleUserId: user.id,
            name: name.data,
          }
        : null;
    })
    .filter((user) => user !== null)
    .toArray()
    .toSorted((left, right) => left.email.localeCompare(right.email));
  if (authorityUsers.length === 0)
    throw new SlackNameIdentityError("authority");
  const actor = snapshot.members.find(
    (member) => member.id === snapshot.actorUserId,
  );
  if (actor === undefined || !activeSlackHuman(actor))
    throw new SlackNameIdentityError("actor");
  const actions = planSlackNameActions(actor, snapshot.members, googleByEmail);
  if (actions.length > MAX_ACTIONS) throw new SlackNameBoundError("action");
  return {
    actions: SlackNameActionSchema.array().parse(
      actions.toSorted((left, right) => left.email.localeCompare(right.email)),
    ),
    actorUserId: snapshot.actorUserId,
    authorityUsers,
    teamId: snapshot.teamId,
  };
}

function planSlackNameActions(
  actor: SlackMember,
  members: readonly SlackMember[],
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
): SlackNameAction[] {
  const actions: SlackNameAction[] = [];
  for (const [email, member] of indexActiveSlackMembers(members)) {
    const action = planSlackNameAction(actor, member, email, googleByEmail);
    if (action !== null) actions.push(action);
  }
  return actions;
}

function indexActiveSlackMembers(
  members: readonly SlackMember[],
): Map<string, SlackMember> {
  const index = new Map<string, SlackMember>();
  for (const member of members) {
    if (!activeSlackHuman(member) || !member.profile.email) continue;
    const email = EmailSchema.parse(member.profile.email);
    if (index.has(email)) throw new SlackNameIdentityError("slack");
    index.set(email, member);
  }
  return index;
}

function planSlackNameAction(
  actor: SlackMember,
  member: SlackMember,
  email: string,
  googleByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
): null | SlackNameAction {
  const googleUser = googleByEmail.get(email);
  const desired = NameSchema.safeParse(googleUser?.name?.fullName);
  if (googleUser === undefined || !desired.success) return null;
  const beforeRealName = member.profile["real_name"]?.trim() ?? "";
  if (!isEmailDefault(beforeRealName, email) || beforeRealName === desired.data)
    return null;
  if (!canActorUpdateTarget(actor, member)) throw new SlackNameRoleError();
  return SlackNameActionSchema.parse({
    beforeRealName,
    desiredName: desired.data,
    email,
    googleUserId: googleUser.id,
    slackUserId: member.id,
    type: "repair-default-name",
  });
}

export async function applySlackNamePlanAction(
  googleUsers: readonly GoogleDirectoryUser[],
  slack: ISlackNameClient,
  expectedTeamId: string,
  rawAction: SlackNameAction,
  expectedPlanHash: string,
  identityBudget?: IdentityWriteBudget,
  assertWriteAuthority?: () => Promise<void>,
): Promise<void> {
  const action = SlackNameActionSchema.parse(rawAction);
  const runId = crypto.randomUUID();
  const snapshot = await slack.listSnapshot(runId);
  const current = await auditSlackNameSnapshot(
    googleUsers,
    snapshot,
    expectedTeamId,
  );
  if (
    current.planHash !== Sha256Schema.parse(expectedPlanHash) ||
    !current.actions.some((candidate) => dequal(candidate, action))
  ) {
    throw new SlackNameDriftError();
  }
  const before = await slack.getProfile(action.slackUserId, runId);
  assertSafeTarget(before, action);
  await reserveIdentityWriteBudget(identityBudget, action.googleUserId);
  if (identityBudget?.required === true) {
    const freshSnapshot = await slack.listSnapshot(runId);
    const freshPlan = await auditSlackNameSnapshot(
      googleUsers,
      freshSnapshot,
      expectedTeamId,
    );
    if (freshPlan.planHash !== current.planHash)
      throw new SlackNameDriftError();
    const beforeTarget = snapshot.members.find(
      ({ id }) => id === action.slackUserId,
    );
    const freshTarget = freshSnapshot.members.find(
      ({ id }) => id === action.slackUserId,
    );
    if (
      !beforeTarget ||
      !freshTarget ||
      slackRoleRank(beforeTarget) !== slackRoleRank(freshTarget)
    )
      throw new SlackNameRoleError();
    assertSafeTarget(await slack.getProfile(action.slackUserId, runId), action);
  }
  await assertWriteAuthority?.();
  await slack.setProfile(action.slackUserId, profilePatch(action), runId);
  assertConverged(await slack.getProfile(action.slackUserId, runId), action);
}

export async function isSlackNameActionConverged(
  slack: Pick<ISlackNameClient, "getProfile">,
  action: SlackNameAction,
): Promise<boolean> {
  return converged(
    await slack.getProfile(action.slackUserId, crypto.randomUUID()),
    action,
  );
}

function profilePatch(action: SlackNameAction) {
  return { "real_name": action.desiredName };
}

function assertSafeTarget(
  profile: SlackProfile,
  action: SlackNameAction,
): void {
  if (
    profile.email === undefined ||
    normalizeIdentityEmail(profile.email) !== action.email ||
    (profile["real_name"]?.trim() ?? "") !== action.beforeRealName ||
    !isEmailDefault(profile["real_name"]?.trim() ?? "", action.email)
  ) {
    throw new SlackNameDriftError();
  }
}

function assertConverged(profile: SlackProfile, action: SlackNameAction): void {
  if (!converged(profile, action)) throw new SlackNameReadbackError();
}

function converged(profile: SlackProfile, action: SlackNameAction): boolean {
  return (
    profile.email !== undefined &&
    normalizeIdentityEmail(profile.email) === action.email &&
    profile["real_name"]?.trim() === action.desiredName
  );
}

function isEmailDefault(name: string, email: string): boolean {
  if (name.length === 0) return false;
  const normalized = name.toLowerCase();
  return normalized === email || normalized === email.split("@", 1)[0];
}

function activeSlackHuman(member: SlackMember): boolean {
  return (
    member.deleted !== true &&
    member["is_bot"] !== true &&
    member["is_app_user"] !== true
  );
}

function canActorUpdateTarget(
  actor: SlackMember,
  target: SlackMember,
): boolean {
  return actor.id === target.id || slackRoleRank(actor) > slackRoleRank(target);
}

function slackRoleRank(member: SlackMember): number {
  if (
    member["is_primary_owner"] === true ||
    member["enterprise_user"]?.["is_primary_owner"] === true
  )
    return 5;
  if (
    member["is_owner"] === true ||
    member["enterprise_user"]?.["is_owner"] === true
  )
    return 4;
  if (
    member["is_admin"] === true ||
    member["enterprise_user"]?.["is_admin"] === true
  )
    return 3;
  if (
    member["is_restricted"] === true ||
    member["is_ultra_restricted"] === true
  )
    return 1;
  return 2;
}

export class SlackNameBoundError extends Error {
  constructor(bound: "action" | "authority", options?: ErrorOptions) {
    super(`slack_name_${bound}_bound_exceeded`, options);
    this.name = "SlackNameBoundError";
  }
}

export class SlackNameIdentityError extends Error {
  constructor(
    source: "actor" | "authority" | "google" | "scope" | "slack" | "workspace",
    options?: ErrorOptions,
  ) {
    super(`slack_name_${source}_identity_ambiguous`, options);
    this.name = "SlackNameIdentityError";
  }
}

export class SlackNameRoleError extends Error {
  constructor() {
    super("slack_name_actor_cannot_update_target");
    this.name = "SlackNameRoleError";
  }
}

export class SlackNameDriftError extends Error {
  constructor() {
    super("slack_name_prewrite_drift");
    this.name = "SlackNameDriftError";
  }
}

export class SlackNameReadbackError extends Error {
  constructor() {
    super("slack_name_readback_failed");
    this.name = "SlackNameReadbackError";
  }
}
