import { dequal } from "dequal";
import type { z } from "zod";

import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import {
  type ActiveResourceLease,
  resourceLeaseKey,
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type { SlackSnapshot } from "../org-sync/org-slack-client.ts";
import { fingerprintNameAuthority } from "../workspace-directory/fingerprint-name-authority.ts";
import {
  type ParentNameEligibility,
  parentNameIdentityEligibility,
} from "../workspace-directory/parent-name-identity-eligibility.ts";
import {
  applySlackNamePlanAction,
  type AuditedSlackNamePlan,
  auditSlackNameSync,
  type ISlackNameClient,
  isSlackNameActionConverged,
  type SlackNameAction,
  SlackNameActionSchema,
  SlackNameDriftError,
} from "../workspace-directory/slack-name-sync.ts";
import type {
  ReviewedAction,
  ReviewedActionContext,
  ReviewedActionState,
} from "./reviewed-action-context.ts";
const SLACK_NAME_LEASE_KEY = resourceLeaseKey(
  "workspace-directory/slack-names",
);
const SLACK_NAME_LEASE_MS = 30 * 60 * 1000;
const SLACK_NAME_MIN_HEADROOM_MS = 6 * 60 * 1000;
export interface SlackNameServiceDependencies {
  directory: Pick<IGoogleDirectoryClient, "listAllUsers">;
  leaseRepository: ResourceLeaseRepository;
  slack: ISlackNameClient;
}
export interface ParentSlackNameCapture {
  diagnostics: {
    googleUserId: string;
    reason: Exclude<ParentNameEligibility, "eligible">;
  }[];
  eligibleActions: SlackNameAction[];
  plan: AuditedSlackNamePlan;
  sourceFingerprint: string;
}
export interface ISlackNameReader {
  capture(): Promise<AuditedSlackNamePlan>;
  captureParent(
    googleUsers?: readonly GoogleDirectoryUser[],
  ): Promise<ParentSlackNameCapture>;
  readReviewed(
    reviewed: ReviewedAction<SlackNameAction>,
  ): Promise<ReviewedActionState>;
  readSourceFingerprint(): Promise<string>;
}
export interface ISlackNameWriter {
  applyReviewed(
    reviewed: ReviewedAction<SlackNameAction>,
    context: ReviewedActionContext<SlackNameAction>,
  ): Promise<"busy" | "completed">;
}
export class SlackNameService implements ISlackNameReader, ISlackNameWriter {
  readonly #dependencies: SlackNameServiceDependencies;
  readonly #writeEnabled: boolean;
  readonly #expectedTeamId: string;
  constructor(
    dependencies: SlackNameServiceDependencies,
    writeEnabled: boolean,
    expectedTeamId: string,
  ) {
    this.#dependencies = dependencies;
    this.#writeEnabled = writeEnabled;
    this.#expectedTeamId = expectedTeamId;
  }
  async capture() {
    return auditSlackNameSync(
      await this.#readGoogleUsers(),
      this.#dependencies.slack,
      this.#expectedTeamId,
    );
  }
  async readReviewed(
    reviewed: ReviewedAction<SlackNameAction>,
  ): Promise<ReviewedActionState> {
    const action = SlackNameActionSchema.parse(reviewed.action);
    if ((await this.#parentEligible(action)) !== "eligible") return "drifted";
    const current = await this.capture();
    if (current.actions.some((candidate) => dequal(candidate, action)))
      return "pending";
    const authority = current.authorityUsers.find(
      ({ googleUserId }) => googleUserId === action.googleUserId,
    );
    // Parent eligibility binds the Slack email to this Google ID, including its aliases.
    if (authority?.name !== action.desiredName) return "drifted";
    return (await isSlackNameActionConverged(this.#dependencies.slack, action))
      ? "converged"
      : "drifted";
  }
  async readSourceFingerprint(): Promise<string> {
    return fingerprintNameAuthority(await this.#readGoogleUsers());
  }
  async captureParent(
    googleUsers?: readonly GoogleDirectoryUser[],
  ): Promise<ParentSlackNameCapture> {
    const [users, snapshot] = await Promise.all([
      googleUsers ?? this.#readGoogleUsers(),
      this.#dependencies.slack.listSnapshot(crypto.randomUUID()),
    ]);
    const plan = await auditSlackNameSync(
      users,
      {
        listSnapshot: () => Promise.resolve(snapshot),
        getProfile: (...args) => this.#dependencies.slack.getProfile(...args),
        setProfile: (...args) => this.#dependencies.slack.setProfile(...args),
      },
      this.#expectedTeamId,
    );
    const eligibility = plan.actions.map((action) =>
      slackNameParentEligibility(users, snapshot, action, this.#expectedTeamId),
    );
    return {
      plan,
      sourceFingerprint: await fingerprintNameAuthority(users),
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
    reviewed: ReviewedAction<SlackNameAction>,
    context: ReviewedActionContext<SlackNameAction>,
  ): Promise<"busy" | "completed"> {
    const { action, expectedPlanHash } = reviewed;
    const identityBudget = context.identityBudget;
    if (!identityBudget.required)
      throw new Error("slack_name_parent_budget_required");
    if (!this.#writeEnabled) throw new Error("slack_name_kill_switch_engaged");
    const execution = await withResourceLease(
      this.#dependencies.leaseRepository,
      SLACK_NAME_LEASE_KEY,
      SLACK_NAME_LEASE_MS,
      async (lease) => {
        await this.#dependencies.leaseRepository.assertActive(
          lease,
          SLACK_NAME_MIN_HEADROOM_MS,
        );
        await this.#apply(action, expectedPlanHash, lease, context);
      },
    );
    return execution.kind === "busy" ? "busy" : "completed";
  }
  async #parentEligible(
    action: SlackNameAction,
  ): Promise<ParentNameEligibility> {
    const [users, snapshot] = await Promise.all([
      this.#readGoogleUsers(),
      this.#dependencies.slack.listSnapshot(crypto.randomUUID()),
    ]);
    return slackNameParentEligibility(
      users,
      snapshot,
      action,
      this.#expectedTeamId,
    );
  }
  async #apply(
    action: z.output<typeof SlackNameActionSchema>,
    expectedPlanHash: string,
    lease: ActiveResourceLease,
    context: ReviewedActionContext<SlackNameAction>,
  ): Promise<void> {
    const googleUsers = await this.#readGoogleUsers();
    const current = await auditSlackNameSync(
      googleUsers,
      this.#dependencies.slack,
      this.#expectedTeamId,
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
    reviewed: ReviewedAction<SlackNameAction>,
    exactPlan: boolean,
    lease: ActiveResourceLease,
    context: Extract<
      ReviewedActionContext<SlackNameAction>,
      {
        mode: "parent";
      }
    >,
  ): Promise<void> {
    if ((await this.#parentEligible(reviewed.action)) !== "eligible")
      throw new SlackNameDriftError();
    await context.verifyPreannouncement(reviewed);
    await context.assertWriteAuthority();
    if (!exactPlan) {
      if ((await this.readReviewed(reviewed)) !== "converged")
        throw new SlackNameDriftError();
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
          throw new SlackNameDriftError();
        await context.assertWriteAuthority();
      },
      () => context.assertFreshPlan(),
    );
  }
  async #applyProvider(
    googleUsers: readonly GoogleDirectoryUser[],
    action: z.output<typeof SlackNameActionSchema>,
    expectedPlanHash: string,
    exactPlan: boolean,
    lease: ActiveResourceLease,
    identityBudget: IdentityWriteBudget,
    assertParentWriteAuthority?: () => Promise<void>,
    assertFreshPlan?: () => void,
  ): Promise<void> {
    if (!exactPlan) {
      if (!(await this.#completedActionStillConverged(googleUsers, action))) {
        throw new SlackNameDriftError();
      }
      return;
    }
    await this.#dependencies.leaseRepository.assertActive(
      lease,
      SLACK_NAME_MIN_HEADROOM_MS,
    );
    await applySlackNamePlanAction(
      googleUsers,
      this.#dependencies.slack,
      this.#expectedTeamId,
      action,
      expectedPlanHash,
      identityBudget,
      async () => {
        await assertParentWriteAuthority?.();
        await this.#dependencies.leaseRepository.assertActive(
          lease,
          SLACK_NAME_MIN_HEADROOM_MS,
        );
        assertFreshPlan?.();
      },
    );
    await this.#dependencies.leaseRepository.assertActive(lease);
  }
  async #completedActionStillConverged(
    googleUsers: readonly GoogleDirectoryUser[],
    action: z.output<typeof SlackNameActionSchema>,
  ): Promise<boolean> {
    const google = googleUsers.find((user) => user.id === action.googleUserId);
    if (google?.name?.fullName?.trim() !== action.desiredName) return false;
    return isSlackNameActionConverged(this.#dependencies.slack, action);
  }
  async #readGoogleUsers() {
    return this.#dependencies.directory.listAllUsers(crypto.randomUUID());
  }
}
export function slackNameParentEligibility(
  users: readonly GoogleDirectoryUser[],
  snapshot: SlackSnapshot,
  action: SlackNameAction,
  expectedTeamId: string,
): ParentNameEligibility {
  const googleEligibility = parentNameIdentityEligibility(
    users,
    action,
    action.desiredName,
  );
  if (googleEligibility !== "eligible") return googleEligibility;
  if (snapshot.teamId !== expectedTeamId)
    throw new Error("slack_name_parent_workspace_changed");
  const matches = snapshot.members.filter(
    ({ id }) => id === action.slackUserId,
  );
  const target = matches[0];
  if (matches.length !== 1 || target === undefined) return "missing-evidence";
  if (target.profile.email?.trim().toLowerCase() !== action.email)
    return "authority-drifted";
  const flags = [
    target.deleted,
    target["is_admin"],
    target["is_owner"],
    target["is_primary_owner"],
    target["is_bot"],
    target["is_app_user"],
    target["is_restricted"],
    target["is_ultra_restricted"],
    ...(target["enterprise_user"] === undefined
      ? []
      : [
          target["enterprise_user"]["is_admin"],
          target["enterprise_user"]["is_owner"],
          target["enterprise_user"]["is_primary_owner"],
        ]),
  ];
  if (flags.includes(true)) return "protected";
  return flags.every((flag) => flag === false)
    ? "eligible"
    : "missing-evidence";
}
