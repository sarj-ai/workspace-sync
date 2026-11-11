import { z } from "zod";

import {
  GoogleUserIdSchema,
  IdentityProviderIdSchema,
} from "../catalog/identity-authority.ts";
import {
  GithubDispatchClaimSchema,
  GithubPrewriteRefusalCategorySchema,
} from "../identity-provisioning/github-zero-dispatch.ts";
import {
  WorkspaceDirectoryAuthorizedActionIdSchema,
  WorkspaceDirectoryWorkflowParamsSchema,
  WorkspaceDirectoryWorkflowResultSchema,
} from "./contracts.ts";
import { WorkspaceDirectoryBranchIdSchema } from "./flow.ts";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const TimeSchema = z.number().int().nonnegative();
const BranchSystem = {
  "access-guard": "linear",
  "drive-org-chart": "google-drive",
  "github-access": "github",
  "identity-provisioning": "google-workspace",
  "slack-groups-channels": "slack",
  "slack-profiles": "slack",
  "trycomp-people": "trycomp",
  "slack-names": "slack",
  "linear-profiles": "linear",
  "google-group-cleanup": "google-workspace",
  "pagerduty-teams": "pagerduty",
  "sentry-memberships": "sentry",
} as const;
const SourceIdentitySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("identity"),
    googleUserId: GoogleUserIdSchema,
    providerAccountId: z.string().min(1),
    systemId: z.union([IdentityProviderIdSchema, z.literal("trycomp")]),
  }),
  z.strictObject({
    kind: z.literal("resource"),
    systemId: z.string().min(1),
    resourceId: z.string().min(1),
  }),
  z.strictObject({
    kind: z.literal("pending-invitation"),
    systemId: z.literal("trycomp"),
    googleUserId: GoogleUserIdSchema,
    email: z.email(),
  }),
]);

/** Evidence pins must be derived by the trusted adapter from the signed plan, not caller authorization. */
export const WorkspaceBranchAttemptPinsSchema = z.strictObject({
  workflowId: DigestSchema,
  paramsDigest: DigestSchema,
  branchId: WorkspaceDirectoryBranchIdSchema,
  actionId: WorkspaceDirectoryAuthorizedActionIdSchema,
  changeKey: z.string().min(1),
  changeSetDigest: DigestSchema.optional(),
  sourceIdentity: SourceIdentitySchema,
  sourceFingerprint: DigestSchema,
  beforeFingerprint: DigestSchema,
  afterFingerprint: DigestSchema,
});
export type WorkspaceBranchAttemptPins = z.output<
  typeof WorkspaceBranchAttemptPinsSchema
>;
export const WorkspaceBranchAttemptClaimSchema =
  WorkspaceBranchAttemptPinsSchema.extend({
    params: WorkspaceDirectoryWorkflowParamsSchema,
    githubDispatchClaim: GithubDispatchClaimSchema.optional(),
  });
export type WorkspaceBranchAttemptClaim = z.output<
  typeof WorkspaceBranchAttemptClaimSchema
>;
export const WorkspaceBranchAttemptVerificationSchema =
  WorkspaceBranchAttemptPinsSchema.extend({
    githubDispatchClaim: GithubDispatchClaimSchema.optional(),
    observedAfterFingerprint: DigestSchema,
    result: WorkspaceDirectoryWorkflowResultSchema.shape.branches.element,
  });
export type WorkspaceBranchAttemptVerification = z.output<
  typeof WorkspaceBranchAttemptVerificationSchema
>;
export const WorkspaceBranchAttemptSchema = z
  .discriminatedUnion("state", [
    WorkspaceBranchAttemptPinsSchema.extend({
      state: z.literal("attempted"),
      githubDispatchClaim: GithubDispatchClaimSchema.optional(),
      attemptedAtMs: TimeSchema,
    }),
    WorkspaceBranchAttemptPinsSchema.extend({
      state: z.literal("not-dispatched"),
      githubDispatchClaim: GithubDispatchClaimSchema,
      attemptedAtMs: TimeSchema,
      refusal: z.strictObject({
        category: GithubPrewriteRefusalCategorySchema,
        operationHash: DigestSchema,
        recordedAtMs: TimeSchema,
      }),
    }),
    WorkspaceBranchAttemptVerificationSchema.extend({
      state: z.literal("verified"),
      attemptedAtMs: TimeSchema,
      verifiedAtMs: TimeSchema,
    }),
  ])
  .superRefine((attempt, context) => {
    if (
      attempt.sourceIdentity.systemId !== BranchSystem[attempt.branchId] ||
      (attempt.sourceIdentity.kind === "resource" &&
        ![
          "drive-org-chart",
          "identity-provisioning",
          "slack-groups-channels",
        ].includes(attempt.branchId))
    ) {
      context.addIssue({
        code: "custom",
        message:
          "branch attempt source identity must belong to its provider and mutation kind",
      });
    }
    if (
      attempt.githubDispatchClaim !== undefined &&
      (attempt.branchId !== "github-access" ||
        attempt.actionId !== "workspace-directory.github-access")
    ) {
      context.addIssue({
        code: "custom",
        message:
          "GitHub dispatch claims must belong to the managed GitHub branch",
      });
    }
    if (
      attempt.state === "not-dispatched" &&
      (attempt.refusal.recordedAtMs < attempt.attemptedAtMs ||
        attempt.refusal.operationHash !==
          attempt.githubDispatchClaim.operationHash)
    ) {
      context.addIssue({
        code: "custom",
        message: "GitHub refusal must follow its original attempt",
      });
    }
    if (attempt.state !== "verified") return;
    if (
      attempt.verifiedAtMs < attempt.attemptedAtMs ||
      attempt.observedAfterFingerprint !== attempt.afterFingerprint ||
      attempt.result.branchId !== attempt.branchId ||
      attempt.result.execution !== "managed" ||
      attempt.result.state !== "applied"
    ) {
      context.addIssue({
        code: "custom",
        message:
          "branch verification must match exact attempted target and successful managed result",
      });
    }
  })
  .meta({ id: "WorkspaceBranchAttempt" });
export type WorkspaceBranchAttempt = z.output<
  typeof WorkspaceBranchAttemptSchema
>;
