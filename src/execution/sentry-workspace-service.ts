import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  type EmployeeEntitlementAuthority,
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import { reserveIdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import {
  type ActiveResourceLease,
  resourceLeaseKey,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type {
  GoogleGroupMember,
  GoogleGroupSnapshot,
} from "../org-sync/channel-model.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type { IGoogleGroupsClient } from "../org-sync/google-groups-client.ts";
import { RetryDeadlineExceededError } from "../org-sync/http.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../org-sync/model.ts";
import {
  type ISentryWorkspaceClient,
  SentryWorkspaceAuthorityBootstrapError,
  SentryWorkspaceAuthorityBootstrapSchema,
  SentryWorkspaceBoundExceededError,
  SentryWorkspaceProviderContractError,
  SentryWorkspaceRequestError,
  SentryWorkspaceUnsupportedCredentialError,
} from "../workspace-directory/sentry-workspace-client.ts";
import {
  applySentryWorkspacePlanAction,
  AuditedSentryWorkspacePlanSchema,
  auditSentryWorkspaceSync,
  isSentryWorkspaceActionConverged,
  type SentryWorkspaceActionSchema,
} from "../workspace-directory/sentry-workspace-sync.ts";
import { getWorkspaceExecutionPolicy } from "./get-workspace-execution-policy.ts";
import type {
  ReviewedActionContext,
  ReviewedActionState,
} from "./reviewed-action-context.ts";
import {
  type ReviewedSentryWorkspace,
  ReviewedSentryWorkspaceSchema,
} from "./reviewed-sentry-workspace.ts";
import {
  applySentryDeprovision,
  captureSentryDeprovisionPlan,
  readSentryDeprovision,
  type SentryDeprovisionPorts,
} from "./sentry-deprovision.ts";
import type { SentryWorkspaceAuthorityPins } from "./sentry-workspace-authority-pins.ts";
import { assertSentryWorkspaceAuthorityPins } from "./sentry-workspace-authority-pins.ts";
const SENTRY_APPLY_LEASE_MS = 30 * 60 * 1000;
const SENTRY_APPLY_MIN_HEADROOM_MS = 6 * 60 * 1000;
const SENTRY_GOOGLE_MEMBER_UNRESOLVED =
  "sentry_workspace_google_member_unresolved";
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
export const SentryWorkspaceParentAuditSchema = z.strictObject({
  authorityFingerprint: Sha256Schema,
  googleIdentities: z.array(
    z.strictObject({ email: z.email(), googleUserId: GoogleUserIdSchema }),
  ),
  plan: AuditedSentryWorkspacePlanSchema,
  providerAuthority: SentryWorkspaceAuthorityBootstrapSchema,
});
type SentryParentEvidenceStage =
  | "google-authority"
  | "provider-authority"
  | "provider-snapshot";
type SentryParentEvidenceReason =
  | "authority-mismatch"
  | "provider-contract"
  | "provider-rate-limited"
  | "provider-timeout"
  | "provider-unavailable"
  | "source-unavailable"
  | "unsupported-credential";
export class SentryParentEvidenceError extends Error {
  readonly reason: SentryParentEvidenceReason;
  readonly stage: SentryParentEvidenceStage;
  constructor(
    stage: SentryParentEvidenceStage,
    reason: SentryParentEvidenceReason,
    options: ErrorOptions,
  ) {
    super("sentry_workspace_parent_evidence_unavailable", options);
    this.name = "SentryParentEvidenceError";
    this.reason = reason;
    this.stage = stage;
  }
}
export interface SentryWorkspaceServiceDependencies {
  directory: SentryDeprovisionPorts["directory"];
  employeeEntitlementAuthority: () => Promise<EmployeeEntitlementAuthority>;
  groups: Pick<IGoogleGroupsClient, "listGroups">;
  leaseRepository: ResourceLeaseRepository;
  sentry: ISentryWorkspaceClient;
}
export interface SentryWorkspaceParentExecution extends Extract<
  ReviewedActionContext<z.output<typeof SentryWorkspaceActionSchema>>,
  {
    mode: "parent";
  }
> {
  assertFinalSourceAuthority(): Promise<void>;
}
export interface SentryWorkspaceServiceContract {
  auditPlan(): ReturnType<typeof auditSentryWorkspaceSync>;
  applyReviewed(
    reviewed: ReviewedSentryWorkspace,
    parent: SentryWorkspaceParentExecution,
  ): Promise<"busy" | "completed">;
  auditParentPlan(): Promise<z.output<typeof SentryWorkspaceParentAuditSchema>>;
  readReviewed(reviewed: ReviewedSentryWorkspace): Promise<ReviewedActionState>;
}
function sentryParentSourceMatches(
  reviewed: ReviewedSentryWorkspace,
  authority: ActiveTeamPlatformAuthority,
): boolean {
  return (
    authority.fingerprint === reviewed.sourceAuthorityFingerprint &&
    authority.googleIdentities.some(
      ({ email, googleUserId }) =>
        email === reviewed.action.email &&
        googleUserId === reviewed.googleUserId,
    )
  );
}
function sameSentryAction(
  left: z.output<typeof SentryWorkspaceActionSchema>,
  right: z.output<typeof SentryWorkspaceActionSchema>,
): boolean {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}
function sameJsonValue(left: unknown, right: unknown): boolean {
  return sameJson(JsonValueSchema.parse(left), JsonValueSchema.parse(right));
}
async function assertSentryActionCapability(
  sentry: ISentryWorkspaceClient,
  action: z.output<typeof SentryWorkspaceActionSchema>,
): Promise<void> {
  if (
    action.type !== "reinvite-expired" ||
    (await isSentryWorkspaceActionConverged(sentry, action))
  )
    return;
  await sentry.assertCanRegenerateInvite();
}
export async function readActiveTeamPlatformEmails(
  directory: Pick<IGoogleDirectoryClient, "listAllUsers">,
  groups: Pick<IGoogleGroupsClient, "listGroups">,
  captureEmployeeEntitlementAuthority: () => Promise<EmployeeEntitlementAuthority>,
): Promise<string[]> {
  const authority = await captureActiveTeamPlatformAuthority(
    directory,
    groups,
    captureEmployeeEntitlementAuthority,
  );
  return authority.activeEmails;
}
class SentryWorkspaceParentDriftError extends Error {
  constructor() {
    super("sentry_workspace_parent_drift");
    this.name = "SentryWorkspaceParentDriftError";
  }
}
interface ActiveTeamPlatformAuthority {
  activeEmails: string[];
  fingerprint: string;
  googleIdentities: {
    email: string;
    googleUserId: string;
  }[];
}
async function captureSentryParentEvidence<T>(
  stage: SentryParentEvidenceStage,
  capture: () => Promise<T>,
): Promise<T> {
  try {
    return await capture();
  } catch (error) {
    throw new SentryParentEvidenceError(
      stage,
      sentryParentEvidenceReason(stage, error),
      {
        cause: error,
      },
    );
  }
}
function sentryParentEvidenceReason(
  stage: SentryParentEvidenceStage,
  error: unknown,
): SentryParentEvidenceReason {
  if (stage === "google-authority") return "source-unavailable";
  const errors = errorChain(error);
  const request = errors.find(
    (candidate): candidate is SentryWorkspaceRequestError =>
      candidate instanceof SentryWorkspaceRequestError,
  );
  if (request?.status === 429) return "provider-rate-limited";
  if (
    request?.status === 408 ||
    errors.some(
      (candidate) => candidate instanceof RetryDeadlineExceededError,
    ) ||
    errors.some((candidate) => candidate.name === "TimeoutError")
  )
    return "provider-timeout";
  if (
    errors.some(
      (candidate) =>
        candidate instanceof SentryWorkspaceAuthorityBootstrapError,
    )
  ) {
    return "authority-mismatch";
  }
  if (
    errors.some(
      (candidate) =>
        candidate instanceof SentryWorkspaceUnsupportedCredentialError,
    )
  ) {
    return "unsupported-credential";
  }
  if (
    errors.some(
      (candidate) =>
        candidate instanceof SentryWorkspaceProviderContractError ||
        candidate instanceof SentryWorkspaceBoundExceededError ||
        candidate instanceof z.ZodError,
    )
  ) {
    return "provider-contract";
  }
  return "provider-unavailable";
}
function errorChain(error: unknown): Error[] {
  const errors: Error[] = [];
  let current = error;
  for (let depth = 0; depth < 4 && current instanceof Error; depth += 1) {
    errors.push(current);
    current = current.cause;
  }
  return errors;
}
async function captureActiveTeamPlatformAuthority(
  directory: Pick<IGoogleDirectoryClient, "listAllUsers">,
  groups: Pick<IGoogleGroupsClient, "listGroups">,
  captureEmployeeEntitlementAuthority: () => Promise<EmployeeEntitlementAuthority>,
  requireGoogleIdentityPins = false,
  usersLast = false,
): Promise<ActiveTeamPlatformAuthority> {
  const runId = crypto.randomUUID();
  const sourceCaptures = [
    groups.listGroups(
      [getWorkspaceExecutionPolicy().sentry.authorityGroupEmail],
      runId,
      undefined,
      true,
    ),
    captureEmployeeEntitlementAuthority(),
  ] as const;
  const [groupSnapshots, employeeEntitlementAuthority, users] = usersLast
    ? [
        ...(await Promise.all(sourceCaptures)),
        await directory.listAllUsers(runId),
      ]
    : await Promise.all([...sourceCaptures, directory.listAllUsers(runId)]);
  const rootGroups = groupSnapshots.filter(
    ({ email }) =>
      normalizeIdentityEmail(email) ===
      getWorkspaceExecutionPolicy().sentry.authorityGroupEmail,
  );
  if (rootGroups.length !== 1) {
    throw new Error("sentry_workspace_google_group_mismatch");
  }
  const activeEmails = activeEmailsFromGroups(
    users,
    groupSnapshots,
    employeeEntitlementAuthority,
  );
  const usersByEmail = indexGoogleUsers(users);
  const googleIdentities = requireGoogleIdentityPins
    ? activeEmails.map((email) => {
        const user = usersByEmail.get(email);
        if (user === undefined)
          throw new Error(SENTRY_GOOGLE_MEMBER_UNRESOLVED);
        return { email, googleUserId: GoogleUserIdSchema.parse(user.id) };
      })
    : [];
  const authoritativeUserIds = new Set(
    groupSnapshots.flatMap(({ members }) =>
      members.filter(({ type }) => type === "USER").map(({ id }) => id),
    ),
  );
  return {
    activeEmails,
    fingerprint: await contentHash({
      activeEmails,
      employeeEntitlementAuthority: {
        complete: employeeEntitlementAuthority.complete,
        excludedEmails: employeeEntitlementAuthority.excludedEmails
          .map(normalizeIdentityEmail)
          .toSorted(),
        excludedGoogleUserIds:
          employeeEntitlementAuthority.excludedGoogleUserIds.toSorted(),
        fingerprint: employeeEntitlementAuthority.fingerprint,
        groupEmail: normalizeIdentityEmail(
          employeeEntitlementAuthority.groupEmail,
        ),
        groupId: employeeEntitlementAuthority.groupId,
      },
      groups: groupSnapshots
        .map(({ email, id, members }) => ({
          email: normalizeIdentityEmail(email),
          id,
          members: members
            .map((member) => ({
              email: normalizeIdentityEmail(member.email),
              id: member.id,
              role: member.role,
              status: member.status,
              type: member.type,
            }))
            .toSorted((left, right) =>
              `${left.type}:${left.id}:${left.email}`.localeCompare(
                `${right.type}:${right.id}:${right.email}`,
              ),
            ),
        }))
        .toSorted((left, right) => left.id.localeCompare(right.id)),
      users: users
        .filter(({ id }) => authoritativeUserIds.has(id))
        .map(
          ({
            aliases,
            archived,
            deletionTime,
            etag,
            id,
            isAdmin,
            isDelegatedAdmin,
            nonEditableAliases,
            primaryEmail,
            suspended,
          }) => ({
            aliases: (aliases ?? []).map(normalizeIdentityEmail).toSorted(),
            archived: archived ?? false,
            deletionTime: deletionTime ?? null,
            etag: etag ?? null,
            id,
            isAdmin: isAdmin ?? null,
            isDelegatedAdmin: isDelegatedAdmin ?? null,
            nonEditableAliases: (nonEditableAliases ?? [])
              .map(normalizeIdentityEmail)
              .toSorted(),
            primaryEmail: normalizeIdentityEmail(primaryEmail),
            suspended: suspended ?? false,
          }),
        )
        .toSorted((left, right) => left.id.localeCompare(right.id)),
    }),
    googleIdentities,
  };
}
function activeEmailsFromGroups(
  users: readonly GoogleDirectoryUser[],
  groups: readonly GoogleGroupSnapshot[],
  employeeEntitlementAuthority: EmployeeEntitlementAuthority,
): string[] {
  if (!hasCompleteEmployeeEntitlementAuthority(employeeEntitlementAuthority)) {
    throw new Error(
      "sentry_workspace_employee_entitlement_authority_incomplete",
    );
  }
  const usersByEmail = indexGoogleUsers(users);
  const active = new Set(
    groups
      .flatMap(({ members }) => members)
      .map((member) => activeGoogleMemberEmail(member, usersByEmail))
      .filter((email): email is string => email !== null),
  );
  for (const [email, user] of usersByEmail) {
    if (
      isEmployeeEntitlementExcluded(
        email,
        user.id,
        employeeEntitlementAuthority,
      )
    ) {
      active.delete(normalizeIdentityEmail(user.primaryEmail));
    }
  }
  if (active.size === 0)
    throw new Error("sentry_workspace_google_authority_empty");
  return [...active].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
}
function indexGoogleUsers(
  users: readonly GoogleDirectoryUser[],
): Map<string, GoogleDirectoryUser> {
  const usersByEmail = new Map<string, GoogleDirectoryUser>();
  for (const user of users) {
    for (const rawEmail of [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ]) {
      const email = normalizeIdentityEmail(rawEmail);
      const current = usersByEmail.get(email);
      if (current !== undefined && current.id !== user.id) {
        throw new Error("sentry_workspace_google_identity_ambiguous");
      }
      usersByEmail.set(email, user);
    }
  }
  return usersByEmail;
}
function activeGoogleMemberEmail(
  member: GoogleGroupMember,
  usersByEmail: ReadonlyMap<string, GoogleDirectoryUser>,
): null | string {
  if (member.type === "GROUP") return null;
  if (member.type !== "USER")
    throw new Error("sentry_workspace_non_user_google_authority");
  if (member.status === "UNKNOWN")
    throw new Error("sentry_workspace_google_member_status_unknown");
  const user = usersByEmail.get(normalizeIdentityEmail(member.email));
  if (user === undefined) throw new Error(SENTRY_GOOGLE_MEMBER_UNRESOLVED);
  if (member.id !== user.id)
    throw new Error("sentry_workspace_google_member_id_mismatch");
  if (
    member.status !== "ACTIVE" ||
    !isActiveGoogleDirectoryUser(user) ||
    protectedIdentityBlocker({
      aliases: [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
      googleUserId: user.id,
      isAdmin: user.isAdmin,
      isDelegatedAdmin: user.isDelegatedAdmin,
      primaryEmail: user.primaryEmail,
    }) !== undefined
  ) {
    return null;
  }
  return normalizeIdentityEmail(user.primaryEmail);
}
export class SentryWorkspaceService implements SentryWorkspaceServiceContract {
  async auditPlan() {
    const { activeEmails } = await captureActiveTeamPlatformAuthority(
      this.#dependencies.directory,
      this.#dependencies.groups,
      this.#dependencies.employeeEntitlementAuthority,
    );
    return auditSentryWorkspaceSync(activeEmails, this.#dependencies.sentry);
  }

  readonly #execution: SentryExecutionMode;
  constructor(
    mode: SentryExecutionMode,
    dependencies: SentryWorkspaceServiceDependencies,
  ) {
    this.#execution = mode;
    this.#dependencies = dependencies;
  }
  readonly #dependencies: SentryWorkspaceServiceDependencies;
  async auditParentPlan() {
    const removal = await captureSentryParentEvidence("google-authority", () =>
      captureSentryDeprovisionPlan(this.#dependencies),
    );
    if (removal !== null)
      return SentryWorkspaceParentAuditSchema.parse(removal);
    const authority = await captureSentryParentEvidence(
      "google-authority",
      () =>
        captureActiveTeamPlatformAuthority(
          this.#dependencies.directory,
          this.#dependencies.groups,
          this.#dependencies.employeeEntitlementAuthority,
          true,
        ),
    );
    const plan = await captureSentryParentEvidence("provider-snapshot", () =>
      auditSentryWorkspaceSync(
        authority.activeEmails,
        this.#dependencies.sentry,
      ),
    );
    const providerAuthority = await captureSentryParentEvidence(
      "provider-authority",
      () => this.#dependencies.sentry.authorityBootstrap(),
    );
    return SentryWorkspaceParentAuditSchema.parse({
      authorityFingerprint: authority.fingerprint,
      googleIdentities: authority.googleIdentities,
      plan,
      providerAuthority,
    });
  }
  async readReviewed(
    reviewed: ReviewedSentryWorkspace,
  ): Promise<ReviewedActionState> {
    const original = ReviewedSentryWorkspaceSchema.parse(reviewed);
    if (original.action.type === "remove-organization-member")
      return readSentryDeprovision(this.#dependencies, original);
    await this.#assertPinnedProviderAuthority(original);
    const authority = await captureActiveTeamPlatformAuthority(
      this.#dependencies.directory,
      this.#dependencies.groups,
      this.#dependencies.employeeEntitlementAuthority,
      true,
    );
    if (!sentryParentSourceMatches(original, authority)) return "drifted";
    const current = await auditSentryWorkspaceSync(
      authority.activeEmails,
      this.#dependencies.sentry,
    );
    if (
      current.planHash === original.expectedPlanHash &&
      current.actions.some((action) =>
        sameSentryAction(action, original.action),
      )
    )
      return "pending";
    return (await isSentryWorkspaceActionConverged(
      this.#dependencies.sentry,
      original.action,
    ))
      ? "converged"
      : "drifted";
  }
  async applyReviewed(
    reviewed: ReviewedSentryWorkspace,
    parent: SentryWorkspaceParentExecution,
  ): Promise<"busy" | "completed"> {
    const original = ReviewedSentryWorkspaceSchema.parse(reviewed);
    const config = this.#execution;
    if (
      this.#execution.kind !== "parent" ||
      config.kind !== "parent" ||
      !parent.identityBudget.required ||
      !sameJsonValue(config.pins, original.authorityPins)
    )
      throw new Error("sentry_workspace_signed_parent_required");
    await parent.verifyPreannouncement({
      action: original.action,
      expectedPlanHash: original.expectedPlanHash,
    });
    const execution = await withResourceLease(
      this.#dependencies.leaseRepository,
      resourceLeaseKey(getWorkspaceExecutionPolicy().sentry.applyLeaseKey),
      SENTRY_APPLY_LEASE_MS,
      async (lease) => {
        await this.#applyReviewedWithinLease(original, parent, lease);
      },
    );
    return execution.kind === "busy" ? "busy" : "completed";
  }
  async #applyReviewedWithinLease(
    original: ReviewedSentryWorkspace,
    parent: SentryWorkspaceParentExecution,
    lease: ActiveResourceLease,
  ): Promise<void> {
    if (original.action.type === "remove-organization-member") {
      await this.#applyRemoval(original, parent, lease);
      return;
    }
    await this.#dependencies.leaseRepository.assertActive(
      lease,
      SENTRY_APPLY_MIN_HEADROOM_MS,
    );
    await this.#assertPinnedProviderAuthority(original);
    const authority = await captureActiveTeamPlatformAuthority(
      this.#dependencies.directory,
      this.#dependencies.groups,
      this.#dependencies.employeeEntitlementAuthority,
      true,
    );
    if (!sentryParentSourceMatches(original, authority)) {
      throw new SentryWorkspaceParentDriftError();
    }
    await assertSentryActionCapability(
      this.#dependencies.sentry,
      original.action,
    );
    const current = await auditSentryWorkspaceSync(
      authority.activeEmails,
      this.#dependencies.sentry,
    );
    if (
      current.planHash !== original.expectedPlanHash ||
      !current.actions.some((action) =>
        sameSentryAction(action, original.action),
      )
    ) {
      if (
        await isSentryWorkspaceActionConverged(
          this.#dependencies.sentry,
          original.action,
        )
      )
        return;
      throw new SentryWorkspaceParentDriftError();
    }
    await reserveIdentityWriteBudget(
      parent.identityBudget,
      original.googleUserId,
    );
    const assertWriteAuthority = async () => {
      await this.#dependencies.leaseRepository.assertActive(
        lease,
        SENTRY_APPLY_MIN_HEADROOM_MS,
      );
      await parent.assertWriteAuthority();
      await this.#assertPinnedProviderAuthority(original);
      await this.#assertExactProviderPlan(original, authority.activeEmails);
      await parent.assertFinalSourceAuthority();
      await this.#assertExactParentSource(original);
      parent.assertFreshPlan();
      if (Date.now() >= lease.expiresAtMs - SENTRY_APPLY_MIN_HEADROOM_MS) {
        throw new SentryWorkspaceParentDriftError();
      }
    };
    await applySentryWorkspacePlanAction(
      authority.activeEmails,
      this.#dependencies.sentry,
      original.action,
      original.expectedPlanHash,
      assertWriteAuthority,
      assertWriteAuthority,
    );
    await this.#dependencies.leaseRepository.assertActive(lease);
  }
  async #applyRemoval(
    original: ReviewedSentryWorkspace,
    parent: SentryWorkspaceParentExecution,
    lease: ActiveResourceLease,
  ): Promise<void> {
    await this.#dependencies.leaseRepository.assertActive(
      lease,
      SENTRY_APPLY_MIN_HEADROOM_MS,
    );
    const current = await readSentryDeprovision(this.#dependencies, original);
    if (current === "converged") return;
    if (current !== "pending") throw new SentryWorkspaceParentDriftError();
    await reserveIdentityWriteBudget(
      parent.identityBudget,
      original.googleUserId,
    );
    await applySentryDeprovision(
      this.#dependencies,
      original,
      async () => {
        await this.#dependencies.leaseRepository.assertActive(
          lease,
          SENTRY_APPLY_MIN_HEADROOM_MS,
        );
        await parent.assertWriteAuthority();
        await parent.assertFinalSourceAuthority();
        parent.assertFreshPlan();
      },
      () => {
        parent.assertFreshPlan();
        if (Date.now() >= lease.expiresAtMs - SENTRY_APPLY_MIN_HEADROOM_MS)
          throw new SentryWorkspaceParentDriftError();
      },
    );
    await this.#dependencies.leaseRepository.assertActive(lease);
  }
  async #assertExactParentSource(
    original: ReviewedSentryWorkspace,
  ): Promise<void> {
    const authority = await captureActiveTeamPlatformAuthority(
      this.#dependencies.directory,
      this.#dependencies.groups,
      this.#dependencies.employeeEntitlementAuthority,
      true,
      true,
    );
    if (!sentryParentSourceMatches(original, authority)) {
      throw new SentryWorkspaceParentDriftError();
    }
  }
  async #assertExactProviderPlan(
    original: ReviewedSentryWorkspace,
    activeEmails: readonly string[],
  ): Promise<void> {
    const current = await auditSentryWorkspaceSync(
      activeEmails,
      this.#dependencies.sentry,
    );
    if (
      current.planHash !== original.expectedPlanHash ||
      !current.actions.some((action) =>
        sameSentryAction(action, original.action),
      )
    ) {
      throw new SentryWorkspaceParentDriftError();
    }
  }
  async #assertPinnedProviderAuthority(
    original: ReviewedSentryWorkspace,
  ): Promise<void> {
    assertSentryWorkspaceAuthorityPins(
      original.authorityPins,
      await this.#dependencies.sentry.authorityBootstrap(),
    );
  }
}
export type SentryExecutionMode =
  | {
      readonly kind: "audit";
    }
  | {
      readonly kind: "parent";
      readonly pins: SentryWorkspaceAuthorityPins;
    };

export type SentryWorkspaceExecutionPort = Omit<
  SentryWorkspaceServiceContract,
  "auditPlan"
>;
