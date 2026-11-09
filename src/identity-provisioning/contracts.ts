import { z } from "zod";

import type {
  AuthorityIdentity,
  DesiredProvisioningPlan,
  ProvisioningProviderId,
} from "../catalog/identity-authority.ts";
import {
  ProviderAccountSchema,
  ProvisioningIdempotencyKeySchema,
  ProvisioningProviderIdSchema,
} from "../catalog/identity-authority.ts";
import type { EmployeeEntitlementAuthority } from "./employee-entitlement-policy.ts";

const Sha256Schema = z
  .string()
  .regex(/^[a-f0-9]{64}$/u)
  .brand<"IdentityProvisioningSha256">();
const ApprovalIdSchema = z.uuid().brand<"IdentityProvisioningApprovalId">();
const ApproverSchema = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .brand<"IdentityProvisioningApprover">();
export const IdentityProvisioningApprovalSchema = z
  .strictObject({
    approvalId: ApprovalIdSchema,
    approvedAtMs: z.number().int().nonnegative(),
    approvedBy: ApproverSchema,
    expiresAtMs: z.number().int().positive(),
    planHash: Sha256Schema,
  })
  .refine(({ approvedAtMs, expiresAtMs }) => expiresAtMs > approvedAtMs, {
    message: "expiresAtMs must be after approvedAtMs",
    path: ["expiresAtMs"],
  })
  .readonly();

export type IdentityProvisioningSha256 = z.output<typeof Sha256Schema>;

const ProviderObservationStructureSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
      account: ProviderAccountSchema,
      kind: z.literal("present"),
      providerId: ProvisioningProviderIdSchema,
    })
    .readonly(),
  z
    .strictObject({
      candidates: z
        .tuple([ProviderAccountSchema])
        .rest(ProviderAccountSchema)
        .readonly(),
      kind: z.literal("ambiguous"),
      providerId: ProvisioningProviderIdSchema,
    })
    .readonly(),
  z
    .strictObject({
      detail: z.string().trim().min(1),
      kind: z.literal("unsupported"),
      providerId: ProvisioningProviderIdSchema,
    })
    .readonly(),
  z
    .strictObject({
      kind: z.literal("absent"),
      providerId: ProvisioningProviderIdSchema,
    })
    .readonly(),
]);

export const ProviderObservationSchema =
  ProviderObservationStructureSchema.superRefine((observation, context) => {
    const accounts =
      observation.kind === "present" ? [observation.account] : [];
    if (observation.kind === "ambiguous")
      accounts.push(...observation.candidates);
    if (
      accounts.some(({ providerId }) => providerId !== observation.providerId)
    ) {
      context.addIssue({
        code: "custom",
        message: "Every observed account must belong to the observed provider",
        path: [observation.kind === "present" ? "account" : "candidates"],
      });
    }
  }).readonly();

export type ProviderObservation = z.output<typeof ProviderObservationSchema>;

export type ProviderPlanningDecision =
  | {
      readonly kind: "satisfied";
      readonly providerId: ProvisioningProviderId;
      readonly subject: AuthorityIdentity;
    }
  | DesiredProvisioningPlan;

export const ProviderApplyReceiptSchema = z
  .strictObject({
    idempotencyKey: ProvisioningIdempotencyKeySchema,
    providerReceiptId: z.string().trim().min(1).brand<"ProviderReceiptId">(),
  })
  .readonly();

export type ProviderApplyReceipt = z.output<typeof ProviderApplyReceiptSchema>;

export const ProviderVerificationSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
      errorCode: z.string().trim().min(1),
      kind: z.literal("mismatch"),
    })
    .readonly(),
  z
    .strictObject({ kind: z.literal("verified"), resultHash: Sha256Schema })
    .readonly(),
]);

export type ProviderVerification = z.output<typeof ProviderVerificationSchema>;

export const ProviderLifecycleActionSchema = z.enum([
  "deprovision",
  "provision",
]);
export type ProviderLifecycleAction = z.output<
  typeof ProviderLifecycleActionSchema
>;
const ProviderLifecycleProtocolBaseShape = {
  authority: z.literal("google-workspace"),
  providerId: ProvisioningProviderIdSchema,
  verification: z.literal("authoritative-readback"),
};
export const ProviderLifecycleProtocolSchema = z
  .discriminatedUnion("execution", [
    z.strictObject({
      ...ProviderLifecycleProtocolBaseShape,
      execution: z.literal("audit-only"),
      managedActions: z.tuple([]).readonly(),
    }),
    z.strictObject({
      ...ProviderLifecycleProtocolBaseShape,
      execution: z.literal("managed"),
      managedActions: z
        .array(ProviderLifecycleActionSchema)
        .min(1)
        .max(2)
        .refine((actions) => new Set(actions).size === actions.length, {
          message: "managedActions must not contain duplicates",
        })
        .readonly(),
    }),
  ])
  .readonly();

export type ProviderLifecycleProtocol = z.output<
  typeof ProviderLifecycleProtocolSchema
>;

export interface IdentityProviderObserver {
  observe(subject: AuthorityIdentity): Promise<ProviderObservation>;
}

export interface IdentityProviderPlanner {
  plan(
    subject: AuthorityIdentity,
    observation: ProviderObservation,
    context?: IdentityProviderPlanningContext,
  ): Promise<ProviderPlanningDecision>;
}

export interface IdentityProviderPlanningContext {
  readonly employeeEntitlementAuthority: EmployeeEntitlementAuthority;
}

export interface IdentityProviderApplier {
  apply(
    plan: Exclude<DesiredProvisioningPlan, { kind: "blocked" }>,
  ): Promise<ProviderApplyReceipt>;
}

export interface IdentityProviderVerifier {
  verify(
    plan: Exclude<DesiredProvisioningPlan, { kind: "blocked" }>,
    receipt: ProviderApplyReceipt,
  ): Promise<ProviderVerification>;
}

interface IdentityProviderConnectorBase
  extends
    IdentityProviderObserver,
    IdentityProviderPlanner,
    IdentityProviderVerifier {
  readonly protocol: ProviderLifecycleProtocol;
  readonly providerId: ProvisioningProviderId;
}

export interface AuditOnlyIdentityProviderConnector extends IdentityProviderConnectorBase {
  readonly execution: "audit-only";
}

export interface ManagedIdentityProviderConnector
  extends IdentityProviderConnectorBase, IdentityProviderApplier {
  readonly execution: "managed";
}

export type IdentityProviderConnector =
  | AuditOnlyIdentityProviderConnector
  | ManagedIdentityProviderConnector;

export function providerLifecycleProtocol(
  input: ProviderLifecycleProtocol,
): ProviderLifecycleProtocol {
  return ProviderLifecycleProtocolSchema.parse(input);
}

export const IdentityProvisioningExecutionPolicySchema = z.discriminatedUnion(
  "kind",
  [
    z
      .strictObject({
        enabledProviders: z.tuple([z.literal("github")]).readonly(),
        kind: z.literal("bounded-automatic-deprovision"),
        maxSubjects: z.literal(1),
      })
      .readonly(),
    z
      .strictObject({
        approval: IdentityProvisioningApprovalSchema,
        enabledProviders: z
          .tuple([ProvisioningProviderIdSchema])
          .rest(ProvisioningProviderIdSchema)
          .readonly()
          .refine((providers) => new Set(providers).size === providers.length, {
            message: "enabledProviders must not contain duplicates",
          }),
        kind: z.literal("approved-apply"),
      })
      .readonly(),
    z.strictObject({ kind: z.literal("audit-only") }).readonly(),
    z
      .strictObject({
        kind: z.literal("kill-switch-engaged"),
        reason: z.string().trim().min(1),
      })
      .readonly(),
  ],
);

export type IdentityProvisioningExecutionPolicy = z.output<
  typeof IdentityProvisioningExecutionPolicySchema
>;

export function identityProvisioningSha256(
  value: string,
): IdentityProvisioningSha256 {
  return Sha256Schema.parse(value);
}

export function identityProvisioningApproval(input: {
  readonly approvalId: string;
  readonly approvedAtMs: number;
  readonly approvedBy: string;
  readonly expiresAtMs: number;
  readonly planHash: string;
}): Extract<
  IdentityProvisioningExecutionPolicy,
  { kind: "approved-apply" }
>["approval"] {
  return IdentityProvisioningApprovalSchema.parse(input);
}
