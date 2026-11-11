import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";

export interface ReviewedAction<Action> {
  readonly action: Action;
  readonly expectedPlanHash: string;
}

export interface ReviewedActionContext<Action> {
  readonly mode: "parent";
  readonly identityBudget: IdentityWriteBudget;
  assertFreshPlan(): void;
  assertWriteAuthority(): Promise<void>;
  verifyPreannouncement(reviewed: ReviewedAction<Action>): Promise<void>;
}

export type ReviewedActionState = "converged" | "drifted" | "pending";
