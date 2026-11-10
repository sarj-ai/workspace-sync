import { z } from "zod";

import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { sha256 } from "../runtime/sha256.ts";
import { logEvent } from "../shared/log-event.ts";
import type { IGoogleDirectoryClient } from "./google-directory-client.ts";
import {
  buildOrgProjectionPlan,
  changedManagedFields,
  type DesiredManagedFields,
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
  type ManagedFieldIds,
  type ManagedFieldName,
  ORG_SYNC_DEPARTMENTS,
  ORG_SYNC_FIELD_LABELS,
  type OrgProjectionPlan,
  type ProfilePlan,
  readManagedFields,
  type SlackMember,
} from "./model.ts";
import type {
  IOrgSlackClient,
  SlackProfileField,
  SlackSnapshot,
} from "./org-slack-client.ts";

const ReviewedPlanSchema = z.object({
  planHash: z.string().regex(/^[a-f0-9]{64}$/u),
  status: z.literal("audit"),
});

const REQUIRED_SLACK_SCOPES = [
  "users.profile:read",
  "users.profile:write",
  "users:read",
  "users:read.email",
] as const;
const PROFILE_SELECTION_POLICY_VERSION = "stable_user_v1";
const PROFILE_REASON_RANK = {
  matched: 0,
  suspended: 1,
  "not_org_participant": 2,
  "slack_orphan": 3,
} as const satisfies Readonly<Record<ProfilePlan["reason"], number>>;
const MAX_RUN_MS = 10 * 60 * 1000;
const ALLOWED_DEPARTMENTS: ReadonlySet<string> = new Set<string>(
  ORG_SYNC_DEPARTMENTS,
);
type ManagedSlackFieldType = "link" | "options_list" | "text" | "user";
type ConfiguredFieldIds = Omit<ManagedFieldIds, "linkedin">;
const LINK_FIELD_TYPES: ReadonlySet<string> = new Set<ManagedSlackFieldType>([
  "link",
]);
const USER_FIELD_TYPES: ReadonlySet<string> = new Set<ManagedSlackFieldType>([
  "user",
]);
const TEAM_FIELD_TYPES: ReadonlySet<string> = new Set<ManagedSlackFieldType>([
  "options_list",
  "text",
]);

export interface OrgSyncConfig {
  allowedEmptyDepartmentGoogleUserIds: string[];
  excludedGoogleUserIds: string[];
  expectedRootGoogleUserIds: string[];
  expectedSlackTeamId: string;
  fieldIds: ConfiguredFieldIds;
  managedDomain: string;
  maxAutomaticChanges: number;
  minimumGoogleParticipants: number;
  protectedDepartedGoogleUserIds: string[];
}

export interface OrgSyncRunOptions {
  expectedPlanHash?: string;
  identityBudget?: IdentityWriteBudget | undefined;
  mode: "audit" | "live";
  trigger: "cron" | "http" | "local";
}

export interface OrgSyncFailure {
  error: string;
  slackUserId: string;
}

export interface OrgSyncRunReport {
  blocked: OrgSyncFailure[];
  changedProfiles: number;
  errors: string[];
  failed: OrgSyncFailure[];
  googleOnly: string[];
  googleParticipants: number;
  matched: number;
  mode: OrgSyncRunOptions["mode"];
  planHash: string;
  planned: ProfilePlan[];
  rootGoogleUserIds: string[];
  runId: string;
  selectedSlackUserId: null | string;
  slackOrphans: string[];
  status: "audit" | "blocked" | "failed" | "success";
  unplacedGoogle: string[];
  verified: number;
  warnings: string[];
  writes: number;
}

export interface OrgSyncServiceOptions {
  config: OrgSyncConfig;
  google: IGoogleDirectoryClient;
  slack: IOrgSlackClient;
}

export interface OrgSyncServiceContract {
  run(
    options: OrgSyncRunOptions,
    googleSnapshot?: readonly GoogleDirectoryUser[],
  ): Promise<OrgSyncRunReport>;
}

export interface SlackProfileSyncContract {
  plan(): Promise<OrgSyncRunReport>;
  apply(
    reviewed: Pick<OrgSyncRunReport, "planHash" | "status">,
    options?: Pick<OrgSyncRunOptions, "identityBudget">,
  ): Promise<OrgSyncRunReport>;
}

export class OrgSyncService
  implements OrgSyncServiceContract, SlackProfileSyncContract
{
  readonly #config: OrgSyncConfig;
  readonly #google: IGoogleDirectoryClient;
  readonly #slack: IOrgSlackClient;

  constructor(options: OrgSyncServiceOptions) {
    this.#config = options.config;
    this.#google = options.google;
    this.#slack = options.slack;
  }

  plan(): Promise<OrgSyncRunReport> {
    return this.run({ mode: "audit", trigger: "local" });
  }

  async apply(
    reviewed: Pick<OrgSyncRunReport, "planHash" | "status">,
    options: Pick<OrgSyncRunOptions, "identityBudget"> = {},
  ): Promise<OrgSyncRunReport> {
    const { planHash } = ReviewedPlanSchema.parse(reviewed);
    return this.run({
      mode: "live",
      trigger: "local",
      expectedPlanHash: planHash,
      identityBudget: options.identityBudget,
    });
  }

  async run(
    options: OrgSyncRunOptions,
    googleSnapshot?: readonly GoogleDirectoryUser[],
  ): Promise<OrgSyncRunReport> {
    const startedAt = Date.now();
    const runId = crypto.randomUUID();
    logEvent("org_sync.run_started", {
      mode: options.mode,
      "run_id": runId,
      trigger: options.trigger,
    });

    try {
      return await this.#executeRun(options, runId, startedAt, googleSnapshot);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent("org_sync.run_failed", {
        error: message,
        "latency_ms": Date.now() - startedAt,
        mode: options.mode,
        "run_id": runId,
        trigger: options.trigger,
      });
      return {
        blocked: [],
        changedProfiles: 0,
        errors: [message],
        failed: [],
        googleOnly: [],
        googleParticipants: 0,
        matched: 0,
        mode: options.mode,
        planHash: "",
        planned: [],
        rootGoogleUserIds: [],
        runId,
        selectedSlackUserId: null,
        slackOrphans: [],
        status: "failed",
        unplacedGoogle: [],
        verified: 0,
        warnings: [],
        writes: 0,
      };
    }
  }

  async #executeRun(
    options: OrgSyncRunOptions,
    runId: string,
    startedAt: number,
    googleSnapshot?: readonly GoogleDirectoryUser[],
  ): Promise<OrgSyncRunReport> {
    const deadlineAt = startedAt + MAX_RUN_MS;
    const slackSnapshot = await this.#slack.listSnapshot(runId, deadlineAt);
    const schema = validateSlackSchema(
      slackSnapshot,
      this.#config.fieldIds,
      this.#config.expectedSlackTeamId,
    );
    const googleUsers = googleSnapshot
      ? [...googleSnapshot]
      : await this.#google.listAllUsers(runId, deadlineAt);
    validateProtectedDepartedUsers(
      googleUsers,
      this.#config.protectedDepartedGoogleUserIds,
    );
    const project = (slackUsers: SlackMember[]) =>
      buildOrgProjectionPlan({
        excludedGoogleUserIds: this.#config.excludedGoogleUserIds,
        expectedRootGoogleUserIds: this.#config.expectedRootGoogleUserIds,
        fieldIds: schema.fieldIds,
        googleUsers,
        managedDomain: this.#config.managedDomain,
        slackUsers,
      });
    const provisionalPlan = project(slackSnapshot.members);
    const exactMembers = await hydrateSlackProfiles(
      this.#slack,
      slackSnapshot.members,
      provisionalPlan,
      this.#config,
      runId,
      deadlineAt,
    );
    const plan = project(exactMembers);
    const changedProfiles = plan.profiles.filter(
      (profile) => profile.changedFields.length > 0,
    );
    try {
      validatePlan(plan, schema, this.#config);
    } catch (error) {
      return finishReport(
        {
          ...reportBase(options, runId, plan, "", changedProfiles.length),
          errors: [error instanceof Error ? error.message : String(error)],
          selectedSlackUserId: null,
          status: "failed",
        },
        startedAt,
      );
    }
    const actor = slackSnapshot.members.find(
      (member) => member.id === slackSnapshot.actorUserId,
    );
    const membersById = new Map(
      exactMembers.map((member) => [member.id, member]),
    );
    const roleSkipped = changedProfiles.filter((profile) => {
      const target = membersById.get(profile.slackUserId);
      return target !== undefined && !canActorUpdateTarget(actor, target);
    });
    const roleSkippedIds = new Set(
      roleSkipped.map((profile) => profile.slackUserId),
    );
    const writableChangedProfiles = changedProfiles.filter(
      (profile) => !roleSkippedIds.has(profile.slackUserId),
    );
    const selectedProfile = selectProfileForWrite(writableChangedProfiles);
    const planHash = await hashPlan(
      plan,
      schema,
      selectedProfile?.slackUserId ?? null,
    );
    logPlan(runId, plan, planHash, selectedProfile);
    const roleWarnings = roleSkipped.map(
      (profile) =>
        `Slack role prevents the installed token from updating ${profile.identity}; retained as audit-only drift`,
    );
    const base = {
      ...reportBase(options, runId, plan, planHash, changedProfiles.length),
      selectedSlackUserId: selectedProfile?.slackUserId ?? null,
      warnings: [...plan.warnings, ...roleWarnings],
    };
    if (options.mode === "audit")
      return finishReport({ ...base, status: "audit" }, startedAt);
    const requiresApproval =
      selectedProfile !== null &&
      (this.#config.maxAutomaticChanges < 1 ||
        selectedProfile.reason === "slack_orphan" ||
        selectedProfile.reason === "not_org_participant");
    if (
      (requiresApproval || options.expectedPlanHash !== undefined) &&
      options.expectedPlanHash !== planHash
    ) {
      const errors = [
        `Safety stop: this exact change set requires approval; set the expected plan hash to ${planHash}`,
      ];
      logEvent("org_sync.mass_change_blocked", {
        changes: selectedProfile === null ? 0 : 1,
        "destructive_clears":
          selectedProfile?.reason === "slack_orphan" ? 1 : 0,
        limit: this.#config.maxAutomaticChanges,
        "plan_hash": planHash,
        "run_id": runId,
      });
      return finishReport({ ...base, errors, status: "blocked" }, startedAt);
    }

    const applied = await this.#applyProfile(
      runId,
      selectedProfile,
      schema.fieldIds,
      deadlineAt,
      options.identityBudget,
    );
    if (Date.now() >= deadlineAt) {
      return finishReport(
        {
          ...base,
          errors: ["Org sync run exceeded its overall deadline"],
          failed: applied.failed,
          status: "failed",
          writes: applied.writes,
        },
        startedAt,
      );
    }
    return finishReport(
      {
        ...base,
        ...applied,
        status: applied.failed.length > 0 ? "failed" : "success",
      },
      startedAt,
    );
  }

  async #applyProfile(
    runId: string,
    profile: ProfilePlan | null,
    fieldIds: ManagedFieldIds,
    deadlineAt: number,
    identityBudget: IdentityWriteBudget | undefined,
  ): Promise<Pick<OrgSyncRunReport, "failed" | "verified" | "writes">> {
    if (profile === null) return { failed: [], verified: 0, writes: 0 };
    try {
      if (Date.now() >= deadlineAt)
        throw new Error("Org sync run exceeded its overall deadline");
      const written = await this.#applyOne(
        runId,
        profile,
        fieldIds,
        deadlineAt,
        identityBudget,
      );
      return { failed: [], verified: 1, writes: written ? 1 : 0 };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logEvent("org_sync.profile_failed", {
        error: message,
        "run_id": runId,
        "slack_user_id": profile.slackUserId,
      });
      return {
        failed: [{ error: message, slackUserId: profile.slackUserId }],
        verified: 0,
        writes: 0,
      };
    }
  }

  async #applyOne(
    runId: string,
    profile: ProfilePlan,
    fieldIds: ManagedFieldIds,
    deadlineAt: number,
    identityBudget: IdentityWriteBudget | undefined,
  ): Promise<boolean> {
    const latest = await this.#slack.getProfile(
      profile.slackUserId,
      runId,
      deadlineAt,
    );
    const current = readManagedFields(latest, fieldIds);
    const changed = changedManagedFields(current, profile.desired, fieldIds);
    if (changed.length === 0) {
      logEvent("org_sync.profile_already_converged", {
        "run_id": runId,
        "slack_user_id": profile.slackUserId,
      });
      return false;
    }
    if (changedManagedFields(current, profile.current, fieldIds).length > 0) {
      throw new Error("Slack profile changed after the reviewed plan");
    }
    const payload = slackProfilePayload(changed, profile.desired, fieldIds);
    logEvent("org_sync.profile_write_started", {
      fields: changed.join(","),
      "run_id": runId,
      "slack_user_id": profile.slackUserId,
    });
    await reserveIdentityWriteBudget(
      identityBudget,
      profile.googleUserId ?? undefined,
    );
    let failure: { error: unknown } | undefined;
    try {
      await this.#slack.setProfile(
        profile.slackUserId,
        payload,
        runId,
        deadlineAt,
      );
    } catch (error) {
      failure = { error };
    }
    const readback = await this.#slack.getProfile(
      profile.slackUserId,
      runId,
      deadlineAt,
    );
    const remaining = changedManagedFields(
      readManagedFields(readback, fieldIds),
      profile.desired,
      fieldIds,
    );
    if (remaining.length > 0) {
      if (failure !== undefined) throw failure.error;
      throw new Error(
        `Slack read-back mismatch for fields: ${remaining.join(",")}`,
      );
    }
    logEvent("org_sync.profile_verified", {
      "run_id": runId,
      "slack_user_id": profile.slackUserId,
    });
    return true;
  }
}

function validateProtectedDepartedUsers(
  users: readonly GoogleDirectoryUser[],
  protectedDepartedGoogleUserIds: readonly string[],
): void {
  const usersById = new Map(users.map((user) => [user.id, user]));
  for (const id of protectedDepartedGoogleUserIds) {
    const user = usersById.get(id);
    if (user && isActiveGoogleDirectoryUser(user)) {
      throw new Error(
        `Protected departed Google account ${id} has been restored to active`,
      );
    }
  }
}

interface ValidatedSlackSchema {
  fieldIds: ManagedFieldIds;
  teamId: string;
  teamOptions: null | Set<string>;
}

async function hydrateSlackProfiles(
  slack: IOrgSlackClient,
  members: SlackMember[],
  plan: OrgProjectionPlan,
  config: Pick<OrgSyncConfig, "minimumGoogleParticipants">,
  runId: string,
  deadlineAt: number,
): Promise<SlackMember[]> {
  if (plan.googleParticipants < config.minimumGoogleParticipants)
    return members;
  const relevantIds = new Set(
    plan.profiles.map((profile) => profile.slackUserId),
  );
  const exactProfiles = new Map<string, SlackMember["profile"]>();
  for (const member of members) {
    if (!relevantIds.has(member.id)) continue;
    if (Date.now() >= deadlineAt) {
      throw new Error("Org sync run exceeded its profile hydration deadline");
    }
    // eslint-disable-next-line no-await-in-loop -- Keep rate-limited profile hydration sequential and check the deadline before each request.
    const profile = await slack.getProfile(member.id, runId, deadlineAt);
    exactProfiles.set(member.id, profile);
  }
  logEvent("org_sync.profile_snapshot", {
    profiles: exactProfiles.size,
    "run_id": runId,
  });
  return members.map((member) => ({
    ...member,
    profile: exactProfiles.get(member.id) ?? member.profile,
  }));
}

function canActorUpdateTarget(
  actor: SlackMember | undefined,
  target: SlackMember,
): boolean {
  if (!actor) return false;
  if (actor["enterprise_user"] || target["enterprise_user"]) {
    if (
      !actor["enterprise_user"] ||
      !target["enterprise_user"] ||
      actor.id === target.id
    )
      return false;
    return slackEnterpriseRoleRank(actor) > slackEnterpriseRoleRank(target);
  }
  if (actor.id === target.id || actor["is_primary_owner"] === true) return true;
  return slackRoleRank(actor) > slackRoleRank(target);
}

function slackEnterpriseRoleRank(member: SlackMember): number {
  const role = member["enterprise_user"];
  if (role?.["is_primary_owner"] === true) return 3;
  if (role?.["is_owner"] === true) return 2;
  if (role?.["is_admin"] === true) return 1;
  return 0;
}

function slackRoleRank(member: SlackMember): number {
  if (member["is_primary_owner"] === true) return 3;
  if (member["is_owner"] === true) return 2;
  if (member["is_admin"] === true) return 1;
  return 0;
}

function validateSlackSchema(
  snapshot: SlackSnapshot,
  configured: ConfiguredFieldIds,
  expectedTeamId: string,
): ValidatedSlackSchema {
  if (snapshot.teamId !== expectedTeamId) {
    throw new Error(
      `Slack token is for unexpected workspace ${snapshot.teamId}`,
    );
  }
  const actor = snapshot.members.find(
    (member) => member.id === snapshot.actorUserId,
  );
  const authorizedActor = actor?.["enterprise_user"]
    ? slackEnterpriseRoleRank(actor) > 0
    : actor?.["is_admin"] === true ||
      actor?.["is_owner"] === true ||
      actor?.["is_primary_owner"] === true;
  if (!authorizedActor) {
    throw new Error(
      "Slack token must belong to a Workspace Admin or Owner, or an Org Admin",
    );
  }
  const requiredScopes = new Set<string>(REQUIRED_SLACK_SCOPES);
  const presentScopes = new Set(snapshot.scopes);
  const missingScopes = [...requiredScopes.difference(presentScopes)];
  if (missingScopes.length > 0) {
    throw new Error(
      `Slack token is missing scopes: ${missingScopes.join(", ")}`,
    );
  }
  const fieldIds = validateSlackManagedFields(snapshot.fields, configured);
  const team = snapshot.fields.find((field) => field.id === fieldIds.team);
  if (!team) throw new Error("Validated Slack Team field disappeared");
  return {
    fieldIds,
    teamId: snapshot.teamId,
    teamOptions: optionValues(team),
  };
}

function validateSlackManagedFields(
  fields: readonly SlackProfileField[],
  configured: ConfiguredFieldIds,
): ManagedFieldIds {
  const fieldsById = new Map(fields.map((field) => [field.id, field]));
  if (fieldsById.size !== fields.length)
    throw new Error("Slack profile schema has duplicate IDs");
  const labels = new Map<string, number>();
  for (const field of fields)
    labels.set(field.label, (labels.get(field.label) ?? 0) + 1);
  for (const label of [
    ORG_SYNC_FIELD_LABELS.reportsTo,
    ORG_SYNC_FIELD_LABELS.manages,
    ORG_SYNC_FIELD_LABELS.team,
  ]) {
    if ((labels.get(label) ?? 0) !== 1)
      throw new Error(`Slack profile field label must be unique: ${label}`);
  }

  const reportsTo = expectField(
    fieldsById,
    configured.reportsTo,
    ORG_SYNC_FIELD_LABELS.reportsTo,
  );
  const manages = expectField(
    fieldsById,
    configured.manages,
    ORG_SYNC_FIELD_LABELS.manages,
  );
  const team = expectField(
    fieldsById,
    configured.team,
    ORG_SYNC_FIELD_LABELS.team,
  );
  if (
    !USER_FIELD_TYPES.has(reportsTo.type) ||
    !USER_FIELD_TYPES.has(manages.type)
  ) {
    throw new Error("Reports to and Manages must both be Slack user fields");
  }
  if (!TEAM_FIELD_TYPES.has(team.type)) {
    throw new Error("Team must be a Slack text or options-list field");
  }
  return { ...configured, linkedin: optionalLinkedInField(fields) };
}

export function optionalLinkedInField(
  fields: readonly SlackProfileField[],
): null | string {
  const candidates = fields.filter(
    (field) => field.label === ORG_SYNC_FIELD_LABELS.linkedin,
  );
  const candidate = candidates.length === 1 ? candidates[0] : undefined;
  if (
    candidate &&
    LINK_FIELD_TYPES.has(candidate.type) &&
    candidate.options?.["is_scim"] !== true
  ) {
    return candidate.id;
  }
  logEvent("org_sync.linkedin_field_unavailable", {
    candidates: candidates.length,
    reason: linkedInUnavailableReason(candidates),
  });
  return null;
}

function linkedInUnavailableReason(
  fields: readonly SlackProfileField[],
): string {
  if (fields.length === 0) return "missing";
  if (fields.length > 1) return "duplicate";
  if (fields[0]?.options?.["is_scim"] === true) return "scim-managed";
  return "wrong-type";
}

function optionValues(field: SlackProfileField): null | Set<string> {
  if (field.type !== "options_list") return null;
  return field["possible_values"]
    ? new Set(field["possible_values"])
    : new Set();
}

function expectField(
  fieldsById: Map<string, SlackProfileField>,
  id: string,
  label: string,
): SlackProfileField {
  if (!id) throw new Error(`Slack field ID is not configured for ${label}`);
  const field = fieldsById.get(id);
  if (!field)
    throw new Error(`Configured Slack field is missing: ${label} (${id})`);
  if (field.label !== label)
    throw new Error(
      `Configured Slack field ${id} is labeled ${field.label}, not ${label}`,
    );
  expectApiManagedField(field, label);
  return field;
}

function expectApiManagedField(field: SlackProfileField, label: string): void {
  const legacyProtected =
    field["is_protected"] === true || field.options?.["is_protected"] === true;
  const apiOnlyPersonFieldWithUnreliableLegacyProtectionFlag =
    label === ORG_SYNC_FIELD_LABELS.manages;
  if (
    !legacyProtected &&
    !apiOnlyPersonFieldWithUnreliableLegacyProtectionFlag
  ) {
    throw new Error(`Slack field must be API-managed/protected: ${label}`);
  }
  if (
    apiOnlyPersonFieldWithUnreliableLegacyProtectionFlag &&
    field.options?.["is_scim"] === true
  ) {
    throw new Error(`Slack field must not be SCIM-managed: ${label}`);
  }
}

function validatePlan(
  plan: OrgProjectionPlan,
  schema: ValidatedSlackSchema,
  config: OrgSyncConfig,
): void {
  if (plan.errors.length > 0)
    throw new Error(`Org projection invalid: ${plan.errors.join("; ")}`);
  if (plan.googleParticipants < config.minimumGoogleParticipants) {
    throw new Error(
      `Google org population ${String(plan.googleParticipants)} is below safety floor ${String(config.minimumGoogleParticipants)}`,
    );
  }
  const expectedRoots = config.expectedRootGoogleUserIds.toSorted((a, b) =>
    a.localeCompare(b),
  );
  if (!expectedRoots.every((id) => plan.rootGoogleUserIds.includes(id))) {
    throw new Error(
      "Google reporting roots do not match the configured immutable root IDs",
    );
  }
  const invalidDepartments = [
    ...new Set(
      plan.participantDepartments
        .map((participant) => participant.department)
        .filter(
          (department) =>
            department !== "" && !ALLOWED_DEPARTMENTS.has(department),
        ),
    ),
  ];
  if (invalidDepartments.length > 0) {
    throw new Error(
      `Google departments are not approved: ${invalidDepartments.join(", ")}`,
    );
  }
  const allowedEmptyIds = new Set(config.allowedEmptyDepartmentGoogleUserIds);
  const unexpectedEmptyDepartments = plan.participantDepartments
    .filter(
      (participant) =>
        participant.department === "" &&
        !allowedEmptyIds.has(participant.userId),
    )
    .map((participant) => participant.userId);
  if (unexpectedEmptyDepartments.length > 0) {
    throw new Error(
      `Google department is empty for non-exempt users: ${unexpectedEmptyDepartments.join(", ")}`,
    );
  }
  if (schema.teamOptions) {
    const configuredTeams = [...schema.teamOptions].toSorted((a, b) =>
      a.localeCompare(b),
    );
    const approvedTeams = [...ALLOWED_DEPARTMENTS].toSorted((a, b) =>
      a.localeCompare(b),
    );
    if (JSON.stringify(configuredTeams) !== JSON.stringify(approvedTeams)) {
      throw new Error(
        "Slack Team options must exactly match the approved department set",
      );
    }
  }
}

function slackProfilePayload(
  changed: ManagedFieldName[],
  desired: DesiredManagedFields,
  fieldIds: ManagedFieldIds,
): {
  fields: Record<string, { alt: string; value: string }>;
  title?: string | undefined;
} {
  const fields: Record<string, { alt: string; value: string }> = {};
  for (const field of changed) {
    if (field === "title") continue;
    const fieldId = fieldIds[field];
    if (fieldId) fields[fieldId] = { alt: "", value: desired[field] };
  }
  return changed.includes("title")
    ? { fields, title: desired.title }
    : { fields };
}

async function hashPlan(
  plan: OrgProjectionPlan,
  schema: ValidatedSlackSchema,
  selectedSlackUserId: null | string,
): Promise<string> {
  const stable = {
    fieldIds: schema.fieldIds,
    googleParticipants: plan.googleParticipants,
    participantDepartments: plan.participantDepartments,
    profiles: plan.profiles.map((profile) => ({
      changedFields: profile.changedFields,
      current: profile.current,
      desired: profile.desired,
      googleUserId: profile.googleUserId,
      reason: profile.reason,
      slackUserId: profile.slackUserId,
    })),
    rootGoogleUserIds: plan.rootGoogleUserIds,
    selectedSlackUserId,
    selectionPolicyVersion: PROFILE_SELECTION_POLICY_VERSION,
    teamId: schema.teamId,
    unplacedGoogle: plan.unplacedGoogle,
  };
  return sha256(JSON.stringify(stable));
}

function reportBase(
  options: OrgSyncRunOptions,
  runId: string,
  plan: OrgProjectionPlan,
  planHash: string,
  changedProfiles: number,
): OrgSyncRunReport {
  return {
    blocked: [],
    changedProfiles,
    errors: [],
    failed: [],
    googleOnly: plan.googleOnly,
    googleParticipants: plan.googleParticipants,
    matched: plan.matched,
    mode: options.mode,
    planHash,
    planned: plan.profiles,
    rootGoogleUserIds: plan.rootGoogleUserIds,
    runId,
    selectedSlackUserId:
      selectProfileForWrite(
        plan.profiles.filter((profile) => profile.changedFields.length > 0),
      )?.slackUserId ?? null,
    slackOrphans: plan.slackOrphans,
    status: "audit",
    unplacedGoogle: plan.unplacedGoogle,
    verified: 0,
    warnings: plan.warnings,
    writes: 0,
  };
}

function selectProfileForWrite(
  profiles: readonly ProfilePlan[],
): null | ProfilePlan {
  return (
    profiles.toSorted(
      (left, right) =>
        PROFILE_REASON_RANK[left.reason] - PROFILE_REASON_RANK[right.reason] ||
        left.slackUserId.localeCompare(right.slackUserId),
    )[0] ?? null
  );
}

function finishReport(
  report: OrgSyncRunReport,
  startedAt: number,
): OrgSyncRunReport {
  logEvent("org_sync.run_completed", {
    blocked: report.blocked.length,
    changes: report.changedProfiles,
    failed: report.failed.length,
    "latency_ms": Date.now() - startedAt,
    matched: report.matched,
    mode: report.mode,
    "plan_hash": report.planHash,
    "run_id": report.runId,
    status: report.status,
    verified: report.verified,
    warnings: report.warnings.length,
    writes: report.writes,
  });
  return report;
}

function logPlan(
  runId: string,
  plan: OrgProjectionPlan,
  planHash: string,
  profile: ProfilePlan | null,
): void {
  logEvent("org_sync.plan_ready", {
    changes: profile === null ? 0 : 1,
    "google_only": plan.googleOnly.length,
    matched: plan.matched,
    "plan_hash": planHash,
    "run_id": runId,
    "slack_orphans": plan.slackOrphans.length,
    warnings: plan.warnings.length,
  });
  if (profile !== null) {
    logEvent("org_sync.profile_diff", {
      fields: profile.changedFields.join(","),
      "google_user_id": profile.googleUserId,
      reason: profile.reason,
      "run_id": runId,
      "slack_user_id": profile.slackUserId,
    });
  }
}
