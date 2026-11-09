import { z } from "zod";

import {
  GoogleUserIdSchema,
  IdentityProviderIdSchema,
} from "../catalog/identity-authority.ts";

export const IdentityBudgetParentKeySchema = z
  .string()
  .regex(
    /^identity-budget:v1:(?:scheduled:organization-sync:(?:0|[1-9][0-9]*)|workflow:[a-f0-9]{64})$/u,
  )
  .brand<"IdentityBudgetParentKey">();
export type IdentityBudgetParentKey = z.output<
  typeof IdentityBudgetParentKeySchema
>;
export const IdentityBudgetServiceIdSchema = z.union([
  IdentityProviderIdSchema,
  z.literal("trycomp"),
]);
export type IdentityBudgetServiceId = z.output<
  typeof IdentityBudgetServiceIdSchema
>;
const ParentInputSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("scheduled"),
    scheduleId: z.literal("organization-sync"),
    scheduledAtMs: z.number().int().nonnegative(),
  }),
  z.strictObject({
    kind: z.literal("workflow"),
    workflowExecutionId: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
]);

export function identityBudgetParentKey(
  input: z.input<typeof ParentInputSchema>,
): IdentityBudgetParentKey {
  const parent = ParentInputSchema.parse(input);
  return IdentityBudgetParentKeySchema.parse(
    parent.kind === "scheduled"
      ? `identity-budget:v1:scheduled:${parent.scheduleId}:${String(parent.scheduledAtMs)}`
      : `identity-budget:v1:workflow:${parent.workflowExecutionId}`,
  );
}

export const IdentityBudgetReservationSchema = z
  .strictObject({
    parentExecutionKey: IdentityBudgetParentKeySchema,
    serviceId: IdentityBudgetServiceIdSchema,
    googleUserId: GoogleUserIdSchema,
    reservedAtMs: z.number().int().nonnegative(),
  })
  .readonly();
export type IdentityBudgetReservation = z.output<
  typeof IdentityBudgetReservationSchema
>;
export const IdentityBudgetReserveInputSchema = z.strictObject({
  parentExecutionKey: IdentityBudgetParentKeySchema,
  serviceId: IdentityBudgetServiceIdSchema,
  googleUserIds: z.array(GoogleUserIdSchema).min(1).max(500),
});

export type IdentityWriteBudget =
  | { readonly required: false }
  | {
      readonly required: true;
      readonly reserve: (googleUserId: string) => Promise<void>;
    };
const BudgetRequiredSchema = z.boolean();
const CallableSchema = z.function();
const BudgetReserveSchema = z.object({
  reserve: z.custom<(googleUserId: string) => Promise<void>>(
    (value) => CallableSchema.safeParse(value).success,
  ),
});

export async function reserveIdentityWriteBudget(
  budget: IdentityWriteBudget | undefined,
  googleUserId: string | undefined,
): Promise<void> {
  if (budget === undefined) return;
  const required = BudgetRequiredSchema.parse(budget.required);
  if (!required) return;
  const parsedBudget = BudgetReserveSchema.safeParse(budget);
  if (!parsedBudget.success)
    throw new Error("identity_budget_callback_required");
  await parsedBudget.data.reserve(GoogleUserIdSchema.parse(googleUserId));
}
