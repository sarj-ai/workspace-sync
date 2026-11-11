import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { LinearProfileActionSchema } from "../workspace-directory/linear-profile-sync.ts";
import { SlackNameActionSchema } from "../workspace-directory/slack-name-sync.ts";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const ReviewedBase = {
  expectedPlanHash: DigestSchema,
  sourceFingerprint: DigestSchema,
};

export const ReviewedSlackNameActionSchema = z.strictObject({
  ...ReviewedBase,
  action: SlackNameActionSchema.extend({
    googleUserId: GoogleUserIdSchema,
    slackUserId: z.string().regex(/^U[A-Z0-9]+$/u),
  }),
  branchId: z.literal("slack-names"),
});
export const ReviewedLinearProfileActionSchema = z.strictObject({
  ...ReviewedBase,
  action: LinearProfileActionSchema.extend({
    googleUserId: GoogleUserIdSchema,
  }),
  branchId: z.literal("linear-profiles"),
});
export const ReviewedNameActionSchema = z.discriminatedUnion("branchId", [
  ReviewedSlackNameActionSchema,
  ReviewedLinearProfileActionSchema,
]);
export type ReviewedNameAction = z.output<typeof ReviewedNameActionSchema>;

type NameSelection<Reviewed> =
  | { kind: "no-eligible-action" }
  | { kind: "selected"; reviewed: Reviewed }
  | { kind: "service-identity-deferred" };

interface NameCapture<Action> {
  eligibleActions: readonly Action[];
  plan: { actions: readonly Action[]; planHash: string };
  sourceFingerprint: string;
}

export function selectReviewedSlackName(
  capture: NameCapture<z.input<typeof SlackNameActionSchema>>,
  serviceGoogleUserId?: string,
): NameSelection<z.output<typeof ReviewedSlackNameActionSchema>> {
  const selected = selectExactEligibleAction(capture, serviceGoogleUserId);
  if (selected.kind !== "selected") return selected;
  return {
    kind: "selected",
    reviewed: ReviewedSlackNameActionSchema.parse({
      branchId: "slack-names",
      action: selected.action,
      expectedPlanHash: capture.plan.planHash,
      sourceFingerprint: capture.sourceFingerprint,
    }),
  };
}

export function selectReviewedLinearProfile(
  capture: NameCapture<z.input<typeof LinearProfileActionSchema>>,
  serviceGoogleUserId?: string,
): NameSelection<z.output<typeof ReviewedLinearProfileActionSchema>> {
  const selected = selectExactEligibleAction(capture, serviceGoogleUserId);
  if (selected.kind !== "selected") return selected;
  return {
    kind: "selected",
    reviewed: ReviewedLinearProfileActionSchema.parse({
      branchId: "linear-profiles",
      action: selected.action,
      expectedPlanHash: capture.plan.planHash,
      sourceFingerprint: capture.sourceFingerprint,
    }),
  };
}

function selectExactEligibleAction<Action extends { googleUserId: string }>(
  capture: {
    eligibleActions: readonly Action[];
    plan: { actions: readonly Action[] };
  },
  serviceGoogleUserId?: string,
) {
  if (serviceGoogleUserId !== undefined)
    GoogleUserIdSchema.parse(serviceGoogleUserId);
  for (const eligible of capture.eligibleActions) {
    if (
      !capture.plan.actions.some((action) =>
        sameJson(
          JsonValueSchema.parse(action),
          JsonValueSchema.parse(eligible),
        ),
      )
    )
      throw new Error("workspace_name_eligible_action_not_in_reviewed_plan");
  }
  const eligible = capture.plan.actions.filter((action) =>
    capture.eligibleActions.some((candidate) =>
      sameJson(JsonValueSchema.parse(action), JsonValueSchema.parse(candidate)),
    ),
  );
  if (eligible.length === 0) return { kind: "no-eligible-action" } as const;
  const selectedAction =
    serviceGoogleUserId === undefined
      ? eligible[0]
      : eligible.find(
          (candidate) => candidate.googleUserId === serviceGoogleUserId,
        );
  return selectedAction === undefined
    ? ({ kind: "service-identity-deferred" } as const)
    : ({ kind: "selected", action: selectedAction } as const);
}

export function reviewedNameSourceIdentity(raw: ReviewedNameAction) {
  const reviewed = ReviewedNameActionSchema.parse(raw);
  return {
    kind: "identity" as const,
    googleUserId: reviewed.action.googleUserId,
    providerAccountId:
      reviewed.branchId === "slack-names"
        ? reviewed.action.slackUserId
        : reviewed.action.linearUserId,
    systemId:
      reviewed.branchId === "slack-names"
        ? ("slack" as const)
        : ("linear" as const),
  };
}

export function reviewedNameManagedSlice(
  raw: ReviewedNameAction,
  state: "converged" | "pending",
) {
  const reviewed = ReviewedNameActionSchema.parse(raw);
  const before =
    reviewed.branchId === "slack-names"
      ? reviewed.action.beforeRealName
      : reviewed.action.beforeFullName;
  const after =
    reviewed.branchId === "slack-names"
      ? reviewed.action.desiredName
      : reviewed.action.desiredFullName;
  return JsonValueSchema.parse({
    ...reviewedNameSourceIdentity(reviewed),
    field: reviewed.branchId === "slack-names" ? "real_name" : "name",
    state,
    value: state === "pending" ? before : after,
  });
}
