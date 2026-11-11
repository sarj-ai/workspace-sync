import { dequal } from "dequal";
import type { z } from "zod";

import {
  type LinearProfileAccount,
  LinearProfileAccountSchema,
} from "../access-guard/linear-provider.ts";
import {
  type EmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import {
  type ActiveResourceLease,
  resourceLeaseKey,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { fingerprintNameAuthority } from "../workspace-directory/fingerprint-name-authority.ts";
import {
  applyLinearProfilePlanAction,
  type AuditedLinearProfilePlan,
  auditLinearProfileSync,
  type ILinearProfileClient,
  isLinearProfileActionConverged,
  type LinearProfileAction,
  LinearProfileActionSchema,
  LinearProfileDriftError,
} from "../workspace-directory/linear-profile-sync.ts";
import {
  type ParentNameEligibility,
  parentNameIdentityEligibility,
} from "../workspace-directory/parent-name-identity-eligibility.ts";
import type {
  ReviewedAction,
  ReviewedActionContext,
  ReviewedActionState,
} from "./reviewed-action-context.ts";
const LINEAR_PROFILE_LEASE_KEY = resourceLeaseKey(
  "workspace-directory/linear-profiles",
);
const LINEAR_PROFILE_LEASE_MS = 30 * 60 * 1000;
const LINEAR_PROFILE_MIN_HEADROOM_MS = 6 * 60 * 1000;
export interface LinearProfileServiceDependencies {
  directory: Pick<IGoogleDirectoryClient, "listAllUsers">;
  employeeEntitlementAuthority: () => Promise<EmployeeEntitlementAuthority>;
  leaseRepository: ResourceLeaseRepository;
  linear: ILinearProfileClient;
}
export interface ParentLinearProfileCapture {
  diagnostics: {
    googleUserId: string;
    reason: Exclude<ParentNameEligibility, "eligible">;
  }[];
  eligibleActions: LinearProfileAction[];
  plan: AuditedLinearProfilePlan;
  sourceFingerprint: string;
}
export interface ILinearProfileReader {
  capture(): Promise<AuditedLinearProfilePlan>;
  captureParent(
    googleUsers?: readonly GoogleDirectoryUser[],
  ): Promise<ParentLinearProfileCapture>;
  readReviewed(
    reviewed: ReviewedAction<LinearProfileAction>,
  ): Promise<ReviewedActionState>;
  readSourceFingerprint(): Promise<string>;
}
export interface ILinearProfileWriter {
  applyReviewed(
    reviewed: ReviewedAction<LinearProfileAction>,
    context: ReviewedActionContext<LinearProfileAction>,
  ): Promise<"busy" | "completed">;
}
export class LinearProfileService
  implements ILinearProfileReader, ILinearProfileWriter
{
  readonly #dependencies: LinearProfileServiceDependencies;
  readonly #writeEnabled: boolean;
  constructor(
    dependencies: LinearProfileServiceDependencies,
    writeEnabled: boolean,
  ) {
    this.#dependencies = dependencies;
    this.#writeEnabled = writeEnabled;
  }
  async capture() {
    return auditLinearProfileSync(
      await this.#readGoogleUsers(),
      this.#dependencies.linear,
    );
  }
  async readReviewed(
    reviewed: ReviewedAction<LinearProfileAction>,
  ): Promise<ReviewedActionState> {
    const action = LinearProfileActionSchema.parse(reviewed.action);
    if ((await this.#parentEligible(action)) !== "eligible") return "drifted";
    const current = await this.capture();
    if (current.actions.some((candidate) => dequal(candidate, action)))
      return "pending";
    const authority = current.authorityUsers.find(
      ({ googleUserId }) => googleUserId === action.googleUserId,
    );
    if (
      authority?.email !== action.email ||
      authority.name !== action.desiredFullName
    )
      return "drifted";
    return (await isLinearProfileActionConverged(
      this.#dependencies.linear,
      action,
    ))
      ? "converged"
      : "drifted";
  }
  async readSourceFingerprint(): Promise<string> {
    const [users, authority] = await Promise.all([
      this.#dependencies.directory.listAllUsers(crypto.randomUUID()),
      this.#dependencies.employeeEntitlementAuthority(),
    ]);
    return fingerprintNameAuthority(users, authority);
  }
  async captureParent(
    googleUsers?: readonly GoogleDirectoryUser[],
  ): Promise<ParentLinearProfileCapture> {
    const [users, authority, accounts] = await Promise.all([
      googleUsers ??
        this.#dependencies.directory.listAllUsers(crypto.randomUUID()),
      this.#dependencies.employeeEntitlementAuthority(),
      this.#dependencies.linear.listProfileAccounts(crypto.randomUUID()),
    ]);
    const eligibleUsers = users.filter(
      (user) =>
        !isEmployeeEntitlementExcluded(user.primaryEmail, user.id, authority),
    );
    const plan = await auditLinearProfileSync(eligibleUsers, {
      listProfileAccounts: () => Promise.resolve(accounts),
      getAccount: (...args) => this.#dependencies.linear.getAccount(...args),
      updateFullName: (...args) =>
        this.#dependencies.linear.updateFullName(...args),
    });
    const eligibility = plan.actions.map((action) =>
      linearProfileParentEligibility(users, authority, accounts, action),
    );
    return {
      plan,
      sourceFingerprint: await fingerprintNameAuthority(users, authority),
      eligibleActions: plan.actions.filter(
        (_action, index) => eligibility[index] === "eligible",
      ),
      diagnostics: plan.actions.flatMap((action, index) => {
        const reason = eligibility[index];
        return reason === undefined || reason === "eligible"
          ? []
          : { googleUserId: action.googleUserId, reason };
      }),
    };
  }
  async applyReviewed(
    reviewed: ReviewedAction<LinearProfileAction>,
    context: ReviewedActionContext<LinearProfileAction>,
  ): Promise<"busy" | "completed"> {
    const executionContext = context;
    const { action, expectedPlanHash } = reviewed;
    const identityBudget = executionContext.identityBudget;
    if (!identityBudget.required)
      throw new Error("linear_profile_parent_budget_required");
    if (!this.#writeEnabled)
      throw new Error("linear_profile_kill_switch_engaged");
    const execution = await withResourceLease(
      this.#dependencies.leaseRepository,
      LINEAR_PROFILE_LEASE_KEY,
      LINEAR_PROFILE_LEASE_MS,
      async (lease) => {
        await this.#dependencies.leaseRepository.assertActive(
          lease,
          LINEAR_PROFILE_MIN_HEADROOM_MS,
        );
        await this.#apply(action, expectedPlanHash, lease, executionContext);
      },
    );
    return execution.kind === "busy" ? "busy" : "completed";
  }
  async #parentEligible(
    action: LinearProfileAction,
  ): Promise<ParentNameEligibility> {
    const [users, authority, account] = await Promise.all([
      this.#dependencies.directory.listAllUsers(crypto.randomUUID()),
      this.#dependencies.employeeEntitlementAuthority(),
      this.#dependencies.linear.getAccount(
        action.linearUserId,
        crypto.randomUUID(),
      ),
    ]);
    return linearProfileParentEligibility(
      users,
      authority,
      [LinearProfileAccountSchema.parse(account)],
      action,
    );
  }
  async #apply(
    action: z.output<typeof LinearProfileActionSchema>,
    expectedPlanHash: string,
    lease: ActiveResourceLease,
    context: ReviewedActionContext<LinearProfileAction>,
  ): Promise<void> {
    const googleUsers = await this.#readGoogleUsers();
    const current = await auditLinearProfileSync(
      googleUsers,
      this.#dependencies.linear,
    );
    const exactPlan =
      current.planHash === expectedPlanHash &&
      current.actions.some((candidate) => dequal(candidate, action));
    {
      return this.#applyParent(
        googleUsers,
        { action, expectedPlanHash },
        exactPlan,
        lease,
        context,
      );
    }
  }
  async #applyParent(
    googleUsers: readonly GoogleDirectoryUser[],
    reviewed: ReviewedAction<LinearProfileAction>,
    exactPlan: boolean,
    lease: ActiveResourceLease,
    context: Extract<
      ReviewedActionContext<LinearProfileAction>,
      {
        mode: "parent";
      }
    >,
  ): Promise<void> {
    if ((await this.#parentEligible(reviewed.action)) !== "eligible")
      throw new LinearProfileDriftError();
    await context.verifyPreannouncement(reviewed);
    await context.assertWriteAuthority();
    if (!exactPlan) {
      if ((await this.readReviewed(reviewed)) !== "converged")
        throw new LinearProfileDriftError();
      return;
    }
    await this.#applyProvider(
      googleUsers,
      reviewed.action,
      reviewed.expectedPlanHash,
      true,
      lease,
      context.identityBudget,
      async () => {
        if ((await this.#parentEligible(reviewed.action)) !== "eligible")
          throw new LinearProfileDriftError();
        await context.assertWriteAuthority();
      },
      () => context.assertFreshPlan(),
    );
  }
  async #applyProvider(
    googleUsers: readonly GoogleDirectoryUser[],
    action: z.output<typeof LinearProfileActionSchema>,
    expectedPlanHash: string,
    exactPlan: boolean,
    lease: ActiveResourceLease,
    identityBudget: IdentityWriteBudget,
    assertParentWriteAuthority?: () => Promise<void>,
    assertFreshPlan?: () => void,
  ): Promise<void> {
    if (!exactPlan) {
      if (!(await this.#completedActionStillConverged(googleUsers, action))) {
        throw new LinearProfileDriftError();
      }
      return;
    }
    await this.#dependencies.leaseRepository.assertActive(
      lease,
      LINEAR_PROFILE_MIN_HEADROOM_MS,
    );
    const assertFinalWriteAuthority = async () => {
      await assertParentWriteAuthority?.();
      await this.#dependencies.leaseRepository.assertActive(
        lease,
        LINEAR_PROFILE_MIN_HEADROOM_MS,
      );
      assertFreshPlan?.();
    };
    await applyLinearProfilePlanAction(
      googleUsers,
      this.#dependencies.linear,
      action,
      expectedPlanHash,
      identityBudget,
      assertFinalWriteAuthority,
      assertParentWriteAuthority === undefined
        ? undefined
        : assertFinalWriteAuthority,
    );
    await this.#dependencies.leaseRepository.assertActive(lease);
  }
  async #completedActionStillConverged(
    googleUsers: readonly GoogleDirectoryUser[],
    action: z.output<typeof LinearProfileActionSchema>,
  ): Promise<boolean> {
    const google = googleUsers.find((user) => user.id === action.googleUserId);
    if (google?.name?.fullName?.trim() !== action.desiredFullName) return false;
    return isLinearProfileActionConverged(this.#dependencies.linear, action);
  }
  async #readGoogleUsers() {
    const [users, authority] = await Promise.all([
      this.#dependencies.directory.listAllUsers(crypto.randomUUID()),
      this.#dependencies.employeeEntitlementAuthority(),
    ]);
    return users.filter(
      (user) =>
        !isEmployeeEntitlementExcluded(user.primaryEmail, user.id, authority),
    );
  }
}
function linearProfileParentEligibility(
  users: readonly GoogleDirectoryUser[],
  authority: EmployeeEntitlementAuthority,
  accounts: readonly LinearProfileAccount[],
  action: LinearProfileAction,
): ParentNameEligibility {
  const googleEligibility = parentNameIdentityEligibility(
    users,
    action,
    action.desiredFullName,
  );
  if (googleEligibility !== "eligible") return googleEligibility;
  if (!authority.complete) return "missing-evidence";
  if (
    isEmployeeEntitlementExcluded(action.email, action.googleUserId, authority)
  )
    return "protected";
  const matches = accounts.filter(({ id }) => id === action.linearUserId);
  const target = matches[0];
  if (matches.length !== 1 || target === undefined) return "missing-evidence";
  if (target.email !== action.email || !target.active)
    return "authority-drifted";
  if (target.admin === true || target.owner === true || target.app === true)
    return "protected";
  return target.admin === false &&
    target.owner === false &&
    target.app === false
    ? "eligible"
    : "missing-evidence";
}
