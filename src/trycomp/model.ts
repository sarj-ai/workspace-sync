import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";

const EmailSchema = z.string().trim().toLowerCase().pipe(z.email());
const DeactivationAuthoritySchema = z.enum([
  "contractor_group",
  "inactive_google",
]);
const TrycompModeSchema = z.enum(["audit", "live"]);
const TrycompRunStatusSchema = z.enum([
  "audit",
  "blocked",
  "converged",
  "failed",
]);
const TrycompReviewedStateSchema = z.enum(["pending", "converged", "drifted"]);

export const TrycompMemberSchema = z.object({
  deactivated: z.boolean(),
  fleetDmLabelId: z.number().int().nullish(),
  id: z.string().trim().min(1),
  isActive: z.boolean(),
  role: z.string().trim().min(1),
  user: z.object({
    email: EmailSchema,
    name: z.string().optional(),
    role: z.string().nullish(),
  }),
});

export type TrycompMember = z.output<typeof TrycompMemberSchema>;

export const TrycompDeactivationResponseSchema = z.object({
  success: z.literal(true),
  deletedMember: z.object({ id: z.string().trim().min(1), email: EmailSchema }),
});

export const TrycompPeopleResponseSchema = z.object({
  count: z.number().int().nonnegative(),
  data: z.array(TrycompMemberSchema),
});

export const TrycompActionSchema = z.discriminatedUnion("type", [
  z.object({
    deactivationAuthority: DeactivationAuthoritySchema.optional(),
    email: EmailSchema,
    memberId: z.string().min(1),
    providerEmail: EmailSchema.optional(),
    type: z.literal("deactivate"),
  }),
  z.object({
    email: EmailSchema,
    memberId: z.string().min(1),
    providerEmail: EmailSchema.optional(),
    type: z.literal("reactivate"),
  }),
  z.object({ email: EmailSchema, type: z.literal("invite") }),
]);

export type TrycompAction = z.output<typeof TrycompActionSchema>;

export const TrycompPlanSchema = z.object({
  actions: z.array(TrycompActionSchema),
  errors: z.array(z.string()),
  planHash: z.string().regex(/^[a-f0-9]{64}$/),
  stats: z.object({
    activeGoogleEmployees: z.number().int().nonnegative(),
    contractorGoogleUsers: z.number().int().nonnegative(),
    trycompMembers: z.number().int().nonnegative(),
  }),
  warnings: z.array(z.string()),
});

export type TrycompPlan = z.output<typeof TrycompPlanSchema>;

export const TrycompReviewedMemberSchema = z.strictObject({
  fleetDmLabelId: z.number().int().nullish(),
  platformRole: z.string().nullish(),
  deactivated: z.boolean(),
  email: EmailSchema,
  id: z.string().trim().min(1),
  isActive: z.boolean(),
  role: z.string().trim().min(1),
});
export type TrycompReviewedMember = z.output<
  typeof TrycompReviewedMemberSchema
>;

export const TrycompSelectedIdentitySchema = z.strictObject({
  googleUserId: GoogleUserIdSchema,
  provider: z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("member"),
      memberId: z.string().min(1),
      email: EmailSchema,
    }),
    z.strictObject({
      kind: z.literal("pending-invitation"),
      email: EmailSchema,
    }),
  ]),
});
export type TrycompSelectedIdentity = z.output<
  typeof TrycompSelectedIdentitySchema
>;

export const TrycompReviewedPlanSchema = z
  .strictObject({
    plan: TrycompPlanSchema.extend({
      actions: z.array(TrycompActionSchema).max(1),
    }),
    schemaVersion: z.literal("trycomp-reviewed/v1"),
    deactivationMode: z
      .enum(["membership-revocation", "device-free-membership-revocation"])
      .optional(),
    sourceFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
    targetBefore: z.array(TrycompReviewedMemberSchema),
    selectedIdentity: TrycompSelectedIdentitySchema.optional(),
  })
  .refine(
    ({ plan, selectedIdentity }) => {
      if (selectedIdentity === undefined) return true;
      const action = plan.actions[0];
      if (action === undefined || plan.errors.length > 0) return false;
      const provider = selectedIdentity.provider;
      return action.type === "invite"
        ? provider.kind === "pending-invitation" &&
            provider.email === action.email
        : provider.kind === "member" &&
            provider.memberId === action.memberId &&
            provider.email === (action.providerEmail ?? action.email);
    },
    {
      message:
        "Selected identity must match the sole error-free reviewed action",
    },
  );
export type TrycompReviewedPlan = z.output<typeof TrycompReviewedPlanSchema>;

export const TrycompReviewedSliceSchema = z.strictObject({
  state: TrycompReviewedStateSchema,
  selectedIdentity: TrycompSelectedIdentitySchema.optional(),
});
export type TrycompReviewedSlice = z.output<typeof TrycompReviewedSliceSchema>;

export const TrycompRunReportSchema = z.strictObject({
  applied: z.array(TrycompActionSchema),
  errors: z.array(z.string()),
  mode: TrycompModeSchema,
  planHash: z.string().regex(/^[a-f0-9]{64}$/u),
  planned: z.array(TrycompActionSchema),
  runId: z.uuid(),
  status: TrycompRunStatusSchema,
  warnings: z.array(z.string()),
});

export type TrycompRunReport = z.output<typeof TrycompRunReportSchema>;
