import { dequal } from "dequal";
import { z } from "zod";

import {
  type AuthoritativeGoogleDirectoryUserState,
  authoritativeGoogleDirectoryUserState,
} from "../identity-lifecycle/contracts.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import {
  type ActiveResourceLease,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type {
  GoogleGroupDirectMembershipRemoval,
  IGoogleGroupMembershipWriter,
  IGoogleGroupsClient,
} from "../org-sync/google-groups-client.ts";
import { defaultSleep, type Sleep } from "../org-sync/http.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  type GoogleGroupCleanupAction,
  GoogleGroupCleanupActionSchema,
  type GoogleGroupCleanupPlan,
  isProtectedGoogleCleanupUser,
  planGoogleGroupCleanup,
} from "../workspace-directory/google-group-cleanup-sync.ts";
import { GOOGLE_GROUP_MUTATION_RESOURCE_LEASE_KEY } from "./google-group-mutation-resource-lease-key.ts";
import type { WorkspaceProviderExecution } from "./provider-execution.ts";
import type {
  ReviewedAction,
  ReviewedActionContext,
  ReviewedActionState,
} from "./reviewed-action-context.ts";
const LIFECYCLE_UNRESOLVED = "google_group_cleanup_lifecycle_unresolved";
const SIGNED_PARENT_REQUIRED = "google_group_cleanup_signed_parent_required";
const APPLY_LEASE_MS = 30 * 60 * 1000;
const APPLY_MIN_HEADROOM_MS = 5 * 60 * 1000;
const READBACK_DELAYS_MS = [250, 500, 1000, 2000] as const;
export interface ManagedGoogleGroupPin {
  readonly email: string;
  readonly id: string;
}
export interface GoogleGroupCleanupServiceDependencies {
  directory: Required<
    Pick<
      IGoogleDirectoryClient,
      "getUserById" | "listAllUsers" | "listDeletedUsers"
    >
  >;
  excludedGoogleGroupIds?: readonly string[];
  excludedGoogleUserIds?: readonly string[];
  groups: Pick<IGoogleGroupsClient, "listAllGroups" | "listGroups">;
  leaseRepository: ResourceLeaseRepository;
  managedGoogleGroupPins: readonly ManagedGoogleGroupPin[];
  writer: IGoogleGroupMembershipWriter;
}
export type GoogleGroupCleanupScheduledResult =
  | "applied"
  | "busy"
  | "converged";
type ApplyResult = Exclude<GoogleGroupCleanupScheduledResult, "busy">;
export type GoogleGroupCleanupParentExecution = Extract<
  ReviewedActionContext<GoogleGroupCleanupAction>,
  {
    mode: "parent";
  }
> & {
  readonly deadlineAtMs?: number;
  assertFinalSourceAuthority(): Promise<void>;
};
export interface GoogleGroupCleanupServiceContract {
  applyReviewed(
    reviewed: ReviewedAction<GoogleGroupCleanupAction>,
    context: GoogleGroupCleanupParentExecution,
  ): Promise<GoogleGroupCleanupScheduledResult>;
  auditPlan(
    runId?: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupCleanupPlan>;
  readReviewed(
    reviewed: ReviewedAction<GoogleGroupCleanupAction>,
    deadlineAt?: number,
  ): Promise<ReviewedActionState>;
}
export interface GoogleGroupCleanupReadbackOptions {
  now?: () => number;
  sleep?: Sleep;
}
export function googleGroupCleanupAuditErrorCode(error: unknown): string {
  if (!(error instanceof Error)) return "unknown_error";
  const [code] = error.message.split(":", 1);
  return code !== undefined && /^google_group_cleanup_[a-z_]+$/u.test(code)
    ? code
    : "unclassified_error";
}
function removalTarget(
  action: GoogleGroupCleanupAction,
): GoogleGroupDirectMembershipRemoval {
  return {
    groupEmail: action.googleGroupEmail,
    groupId: action.googleGroupId,
    memberEmail: action.memberEmail,
    memberId: action.memberId,
    ...(action.role !== undefined && { role: action.role }),
  };
}
function sameAction(
  left: GoogleGroupCleanupAction,
  right: GoogleGroupCleanupAction,
): boolean {
  return dequal(left, right);
}
const PinnedEmailSchema = z.email();
function assertValidPins(pins: readonly ManagedGoogleGroupPin[]): void {
  if (pins.length === 0)
    throw new Error("google_group_cleanup_managed_group_pins_empty");
  const ids = new Set<string>();
  const emails = new Set<string>();
  for (const pin of pins) {
    const email = PinnedEmailSchema.parse(pin.email).toLowerCase();
    if (!pin.id.trim())
      throw new Error("google_group_cleanup_managed_group_pin_id_empty");
    if (ids.has(pin.id) || emails.has(email)) {
      throw new Error("google_group_cleanup_managed_group_pin_duplicate");
    }
    ids.add(pin.id);
    emails.add(email);
  }
}
function assertPinnedSnapshots(
  pins: readonly ManagedGoogleGroupPin[],
  groups: readonly GoogleGroupSnapshot[],
): void {
  if (groups.length !== pins.length)
    throw new Error("google_group_cleanup_group_pin_mismatch");
  const byId = new Map(groups.map((group) => [group.id, group]));
  for (const pin of pins) {
    const group = byId.get(pin.id);
    if (group?.email.toLowerCase() !== pin.email.toLowerCase()) {
      throw new Error("google_group_cleanup_group_pin_mismatch");
    }
  }
}
export class GoogleGroupCleanupService implements GoogleGroupCleanupServiceContract {
  readonly #execution: WorkspaceProviderExecution;
  constructor(
    mode: WorkspaceProviderExecution,
    dependencies: GoogleGroupCleanupServiceDependencies,
    readback: GoogleGroupCleanupReadbackOptions = {},
  ) {
    this.#dependencies = dependencies;
    this.#execution = mode;
    this.#now = readback.now ?? Date.now;
    this.#sleep = readback.sleep ?? defaultSleep;
    assertValidPins(dependencies.managedGoogleGroupPins);
  }
  readonly #dependencies: GoogleGroupCleanupServiceDependencies;
  readonly #now: () => number;
  readonly #sleep: Sleep;
  async auditPlan(
    runId: string = crypto.randomUUID(),
    deadlineAt?: number,
  ): Promise<GoogleGroupCleanupPlan> {
    const [liveUsers, deletedUsers, groupInventory] = await Promise.all([
      this.#dependencies.directory.listAllUsers(runId, deadlineAt),
      this.#dependencies.directory.listDeletedUsers(runId, deadlineAt),
      this.#dependencies.groups.listAllGroups(runId, deadlineAt),
    ]);
    const inventoryPins = groupInventory.map(({ email, id }) => ({
      email,
      id,
    }));
    const groups = await this.#dependencies.groups.listGroups(
      inventoryPins.map(({ email }) => email),
      runId,
      deadlineAt,
      false,
      true,
    );
    assertPinnedSnapshots(inventoryPins, groups);
    const plan = await planGoogleGroupCleanup({
      directoryUsers: [...liveUsers, ...deletedUsers],
      ...(!(this.#dependencies.excludedGoogleGroupIds === undefined) && {
        excludedGoogleGroupIds: this.#dependencies.excludedGoogleGroupIds,
      }),
      ...(!(this.#dependencies.excludedGoogleUserIds === undefined) && {
        excludedGoogleUserIds: this.#dependencies.excludedGoogleUserIds,
      }),
      managedGoogleGroupPins: inventoryPins,
      managedGoogleGroups: groups,
    });
    const [firstAction] = plan.actions;
    if (firstAction !== undefined) {
      await this.#dependencies.writer.auditDirectMember(
        removalTarget(firstAction),
        runId,
        deadlineAt,
      );
    }
    return plan;
  }
  async readReviewed(
    reviewed: ReviewedAction<GoogleGroupCleanupAction>,
    deadlineAt?: number,
  ): Promise<ReviewedActionState> {
    const action = GoogleGroupCleanupActionSchema.parse(reviewed.action);
    const runId = crypto.randomUUID();
    if (await this.#isConvergedAndStillAuthorized(action, runId, deadlineAt))
      return "converged";
    const plan = await this.auditPlan(runId, deadlineAt);
    if (
      plan.planHash === reviewed.expectedPlanHash &&
      plan.actions.some((item) => sameAction(item, action))
    )
      return "pending";
    return "drifted";
  }
  async applyReviewed(
    reviewed: ReviewedAction<GoogleGroupCleanupAction>,
    context: GoogleGroupCleanupParentExecution,
  ): Promise<GoogleGroupCleanupScheduledResult> {
    if (this.#execution.kind !== "parent" || !context.identityBudget.required)
      throw new Error(SIGNED_PARENT_REQUIRED);
    await context.verifyPreannouncement(reviewed);
    context.assertFreshPlan();
    return this.#applySerialized(
      reviewed.action,
      reviewed.expectedPlanHash,
      crypto.randomUUID(),
      context.identityBudget,
      context,
    );
  }
  async #applySerialized(
    action: GoogleGroupCleanupAction,
    expectedPlanHash: string,
    runId: string,
    identityBudget: IdentityWriteBudget,
    parent: GoogleGroupCleanupParentExecution,
  ): Promise<GoogleGroupCleanupScheduledResult> {
    if (this.#execution.kind !== "parent")
      throw new Error("google_group_cleanup_kill_switch_engaged");
    const execution = await withResourceLease(
      this.#dependencies.leaseRepository,
      GOOGLE_GROUP_MUTATION_RESOURCE_LEASE_KEY,
      APPLY_LEASE_MS,
      async (lease) => {
        await this.#dependencies.leaseRepository.assertActive(
          lease,
          APPLY_MIN_HEADROOM_MS,
        );
        return this.#apply(
          action,
          expectedPlanHash,
          lease,
          runId,
          identityBudget,
          parent,
        );
      },
    );
    if (execution.kind === "busy") return "busy";
    return execution.result;
  }
  async #apply(
    rawAction: GoogleGroupCleanupAction,
    expectedPlanHash: string,
    lease: ActiveResourceLease,
    runId: string,
    identityBudget: IdentityWriteBudget,
    parent: GoogleGroupCleanupParentExecution,
  ): Promise<ApplyResult> {
    const action = GoogleGroupCleanupActionSchema.parse(rawAction);
    const deadlineAt = Math.min(
      parent.deadlineAtMs ?? Infinity,
      lease.expiresAtMs - APPLY_MIN_HEADROOM_MS,
    );
    const current = await this.auditPlan(runId, deadlineAt);
    const exactPlan =
      current.planHash === expectedPlanHash &&
      current.actions.some((item) => sameAction(item, action));
    {
      await parent.assertWriteAuthority();
      parent.assertFreshPlan();
      return this.#applyProvider(
        action,
        expectedPlanHash,
        exactPlan,
        lease,
        runId,
        identityBudget,
        parent,
      );
    }
  }
  async #applyProvider(
    action: GoogleGroupCleanupAction,
    expectedPlanHash: string,
    exactPlan: boolean,
    lease: ActiveResourceLease,
    runId: string,
    identityBudget: IdentityWriteBudget,
    parent: GoogleGroupCleanupParentExecution,
  ): Promise<ApplyResult> {
    const deadlineAt = Math.min(
      parent.deadlineAtMs ?? Infinity,
      lease.expiresAtMs - APPLY_MIN_HEADROOM_MS,
    );
    if (!exactPlan) {
      if (
        !(await this.#isConvergedAndStillAuthorized(action, runId, deadlineAt))
      ) {
        throw new Error("google_group_cleanup_prewrite_drift");
      }
      return "converged";
    }
    const prewrite = await this.auditPlan(runId, deadlineAt);
    if (
      prewrite.planHash !== expectedPlanHash ||
      !prewrite.actions.some((item) => sameAction(item, action))
    ) {
      throw new Error("google_group_cleanup_prewrite_drift");
    }
    await this.#assertFreshInactiveLifecycle(action, runId, deadlineAt);
    await this.#dependencies.leaseRepository.assertActive(
      lease,
      APPLY_MIN_HEADROOM_MS,
    );
    await reserveIdentityWriteBudget(identityBudget, action.googleUserId);
    await this.#assertFreshInactiveLifecycle(action, runId, deadlineAt);
    await this.#dependencies.leaseRepository.assertActive(
      lease,
      APPLY_MIN_HEADROOM_MS,
    );
    const result = await this.#dependencies.writer.removeDirectMember(
      removalTarget(action),
      runId,
      deadlineAt,
      undefined,
      {
        assertFinalSourceAuthority: async () => {
          await this.#dependencies.leaseRepository.assertActive(
            lease,
            APPLY_MIN_HEADROOM_MS,
          );
          await parent.assertFinalSourceAuthority();
          await this.#assertFreshInactiveLifecycle(action, runId, deadlineAt);
          parent.assertFreshPlan();
        },
        assertFreshPlan: () => {
          parent.assertFreshPlan();
          if (Date.now() >= lease.expiresAtMs - APPLY_MIN_HEADROOM_MS)
            throw new Error("google_group_cleanup_prewrite_drift");
        },
        assertWriteAuthority: async () => {
          await parent.assertWriteAuthority();
          await this.#assertFreshInactiveLifecycle(action, runId, deadlineAt);
          await this.#dependencies.leaseRepository.assertActive(
            lease,
            APPLY_MIN_HEADROOM_MS,
          );
          parent.assertFreshPlan();
        },
      },
    );
    if (!result.wrote)
      throw new Error("google_group_cleanup_writer_did_not_mutate");
    await this.#verifyReadback(action, lease, runId, deadlineAt);
    return "applied";
  }
  async #verifyReadback(
    action: GoogleGroupCleanupAction,
    lease: ActiveResourceLease,
    runId: string,
    deadlineAt: number,
    attempt = 0,
  ): Promise<void> {
    this.#assertReadbackDeadline(deadlineAt);
    await this.#dependencies.leaseRepository.assertActive(lease);
    this.#assertReadbackDeadline(deadlineAt);
    const group = await this.#readTargetGroup(action, runId, deadlineAt);
    this.#assertReadbackDeadline(deadlineAt);
    await this.#assertFreshInactiveLifecycle(action, runId, deadlineAt);
    await this.#dependencies.leaseRepository.assertActive(lease);
    this.#assertReadbackDeadline(deadlineAt);
    const pending = group.members.filter(({ id }) => id === action.memberId);
    if (pending.length === 0) return;
    const [member] = pending;
    if (
      pending.length !== 1 ||
      member?.type !== "USER" ||
      member.role !== (action.role ?? "MEMBER") ||
      member.email.toLowerCase() !== action.memberEmail.toLowerCase()
    ) {
      throw new Error("google_group_cleanup_prewrite_drift");
    }
    const delayMs = READBACK_DELAYS_MS[attempt];
    if (delayMs === undefined)
      throw new Error("google_group_cleanup_readback_failed");
    this.#assertReadbackDeadline(deadlineAt, delayMs);
    await this.#sleep(delayMs);
    await this.#verifyReadback(action, lease, runId, deadlineAt, attempt + 1);
  }
  #assertReadbackDeadline(deadlineAt: number, waitMs = 0): void {
    if (this.#now() + waitMs >= deadlineAt) {
      throw new Error("google_group_cleanup_readback_failed");
    }
  }
  async #assertFreshInactiveLifecycle(
    action: GoogleGroupCleanupAction,
    runId: string,
    deadlineAt?: number,
  ): Promise<AuthoritativeGoogleDirectoryUserState> {
    if (
      this.#dependencies.excludedGoogleUserIds?.includes(
        action.googleUserId,
      ) === true
    ) {
      throw new Error("google_group_cleanup_protected_user");
    }
    const live = await this.#dependencies.directory.getUserById(
      action.googleUserId,
      runId,
      deadlineAt,
    );
    let user: GoogleDirectoryUser | undefined = live ?? undefined;
    if (live === null) {
      const deleted = await this.#dependencies.directory.listDeletedUsers(
        runId,
        deadlineAt,
      );
      const matches = deleted.filter(({ id }) => id === action.googleUserId);
      if (matches.length !== 1) throw new Error(LIFECYCLE_UNRESOLVED);
      [user] = matches;
    }
    if (user === undefined) throw new Error(LIFECYCLE_UNRESOLVED);
    if (isProtectedGoogleCleanupUser(user))
      throw new Error("google_group_cleanup_protected_user");
    const authority = authoritativeGoogleDirectoryUserState(user);
    const authorityEmail =
      authority.state === "deleted"
        ? authority.lastKnownPrimaryEmail
        : authority.primaryEmail;
    if (
      authority.googleUserId !== action.googleUserId ||
      authority.state !== action.lifecycle ||
      authorityEmail?.toLowerCase() !== action.authorityEmail?.toLowerCase()
    ) {
      throw new Error("google_group_cleanup_lifecycle_changed");
    }
    return authority;
  }
  async #isConvergedAndStillAuthorized(
    action: GoogleGroupCleanupAction,
    runId: string,
    deadlineAt?: number,
  ): Promise<boolean> {
    const group = await this.#readTargetGroup(action, runId, deadlineAt);
    return group.members.every(({ id }) => id !== action.memberId);
  }
  async #readTargetGroup(
    action: GoogleGroupCleanupAction,
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleGroupSnapshot> {
    await this.#assertFreshInactiveLifecycle(action, runId, deadlineAt);
    const groups = await this.#dependencies.groups.listGroups(
      [action.googleGroupEmail],
      runId,
      deadlineAt,
      false,
      true,
    );
    assertPinnedSnapshots(
      [{ email: action.googleGroupEmail, id: action.googleGroupId }],
      groups,
    );
    const [group] = groups;
    if (group === undefined)
      throw new Error("google_group_cleanup_group_pin_mismatch");
    return group;
  }
}
