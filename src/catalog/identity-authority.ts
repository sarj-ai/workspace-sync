import { z } from "zod";

const NonBlankTextSchema = z.string().trim().min(1);

const IsoInstantSchema = z.iso.datetime({ offset: true }).brand<"IsoInstant">();

export const GoogleUserIdSchema = z
  .string()
  .regex(/^[1-9]\d*$/u)
  .brand<"GoogleUserId">();
export const GitHubUserIdSchema = z
  .string()
  .regex(/^[1-9]\d*$/u)
  .brand<"GitHubUserId">();
export const GitHubLoginSchema = z
  .string()
  .min(1)
  .max(39)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9]))*$/u)
  .transform((value) => value.toLowerCase())
  .brand<"GitHubLogin">();
export const PrimaryEmailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .pipe(z.email())
  .brand<"PrimaryEmail">();
export const AuthorityRevisionSchema =
  NonBlankTextSchema.brand<"AuthorityRevision">();
export const ProviderAccountIdSchema =
  NonBlankTextSchema.brand<"ProviderAccountId">();
export const ProvisioningIdempotencyKeySchema = z
  .string()
  .regex(
    /^identity:v1:\d+:(?:ashby|attio|github|linear|pagerduty|slack):(?:provision|deprovision):[a-f0-9]{64}$/u,
  )
  .brand<"ProvisioningIdempotencyKey">();

export const IdentityProviderIdSchema = z.enum([
  "ashby",
  "attio",
  "github",
  "google-workspace",
  "linear",
  "pagerduty",
  "sentry",
  "slack",
]);
export const ProvisioningProviderIdSchema = z.enum([
  "ashby",
  "attio",
  "github",
  "linear",
  "pagerduty",
  "slack",
]);
const NonGitHubProvisioningProviderIdSchema = z.enum([
  "ashby",
  "attio",
  "linear",
  "pagerduty",
  "slack",
]);

export const InactiveAuthorityLifecycleSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("suspended") }).readonly(),
  z.strictObject({ kind: z.literal("archived") }).readonly(),
  z.strictObject({ kind: z.literal("deleted") }).readonly(),
]);

export const VerifiedGitHubIdentitySchema = z
  .strictObject({
    githubLogin: GitHubLoginSchema,
    githubUserId: GitHubUserIdSchema,
    kind: z.literal("verified"),
    verifiedAt: IsoInstantSchema,
  })
  .readonly();
export const GitHubIdentityCandidateSchema = z
  .strictObject({
    githubLogin: GitHubLoginSchema,
    githubUserId: GitHubUserIdSchema,
  })
  .readonly();
export const GitHubIdentityStateSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("unlinked") }).readonly(),
  VerifiedGitHubIdentitySchema,
  z
    .strictObject({
      candidates: z
        .tuple([GitHubIdentityCandidateSchema])
        .rest(GitHubIdentityCandidateSchema)
        .readonly(),
      kind: z.literal("conflict"),
      reason: z.enum([
        "ambiguous-match",
        "duplicate-login",
        "id-login-mismatch",
      ]),
    })
    .readonly(),
]);

const AuthorityIdentityBaseShape = {
  aliases: z.array(PrimaryEmailSchema).readonly().optional(),
  authorityRevision: AuthorityRevisionSchema,
  github: GitHubIdentityStateSchema,
  googleUserId: GoogleUserIdSchema,
  isAdmin: z.boolean().optional(),
  isDelegatedAdmin: z.boolean().optional(),
  observedAt: IsoInstantSchema,
  primaryEmail: PrimaryEmailSchema,
};
export const ActiveAuthorityIdentitySchema = z
  .strictObject({
    ...AuthorityIdentityBaseShape,
    lifecycle: z.strictObject({ kind: z.literal("active") }).readonly(),
  })
  .readonly();
export const ActiveVerifiedAuthorityIdentitySchema = z
  .strictObject({
    ...AuthorityIdentityBaseShape,
    github: VerifiedGitHubIdentitySchema,
    lifecycle: z.strictObject({ kind: z.literal("active") }).readonly(),
  })
  .readonly();
export const InactiveAuthorityIdentitySchema = z
  .strictObject({
    ...AuthorityIdentityBaseShape,
    lifecycle: InactiveAuthorityLifecycleSchema,
  })
  .readonly();
export const AuthorityIdentitySchema = z.union([
  ActiveAuthorityIdentitySchema,
  InactiveAuthorityIdentitySchema,
]);

export const GitHubProviderAccountSchema = z
  .strictObject({
    githubLogin: GitHubLoginSchema,
    githubUserId: GitHubUserIdSchema,
    providerId: z.literal("github"),
  })
  .readonly();
export const NonGitHubProviderAccountSchema = z
  .strictObject({
    accountId: ProviderAccountIdSchema,
    providerId: NonGitHubProvisioningProviderIdSchema,
  })
  .readonly();
export const ProviderAccountSchema = z.union([
  GitHubProviderAccountSchema,
  NonGitHubProviderAccountSchema,
]);

const PlanBaseShape = {
  idempotencyKey: ProvisioningIdempotencyKeySchema,
};
const GitHubProvisionPlanSchema = z
  .strictObject({
    ...PlanBaseShape,
    kind: z.literal("provision"),
    subject: ActiveVerifiedAuthorityIdentitySchema,
    target: GitHubProviderAccountSchema,
  })
  .readonly()
  .refine((plan) => planIdempotencyKeyMatches(plan, "provision"), {
    message: "idempotency key must identify this subject, provider, and action",
    path: ["idempotencyKey"],
  })
  .refine(
    (plan) =>
      plan.subject.github.githubUserId === plan.target.githubUserId &&
      plan.subject.github.githubLogin === plan.target.githubLogin,
    {
      message: "GitHub target must equal the verified authority identity",
      path: ["target"],
    },
  );
const NonGitHubProvisionPlanSchema = z
  .strictObject({
    ...PlanBaseShape,
    kind: z.literal("provision"),
    subject: ActiveAuthorityIdentitySchema,
    target: NonGitHubProviderAccountSchema,
  })
  .readonly()
  .refine((plan) => planIdempotencyKeyMatches(plan, "provision"), {
    message: "idempotency key must identify this subject, provider, and action",
    path: ["idempotencyKey"],
  });
const DeprovisionPlanSchema = z
  .strictObject({
    ...PlanBaseShape,
    kind: z.literal("deprovision"),
    subject: InactiveAuthorityIdentitySchema,
    target: ProviderAccountSchema,
  })
  .readonly()
  .refine((plan) => planIdempotencyKeyMatches(plan, "deprovision"), {
    message: "idempotency key must identify this subject, provider, and action",
    path: ["idempotencyKey"],
  });
export const ProvisioningBlockerSchema = z
  .strictObject({
    code: z.enum([
      "authority-conflict",
      "identity-unlinked",
      "provider-ambiguous",
      "provider-unsupported",
      "safety-policy",
    ]),
    detail: NonBlankTextSchema,
  })
  .readonly();
const BlockedProvisioningPlanSchema = z
  .strictObject({
    blockers: z
      .tuple([ProvisioningBlockerSchema])
      .rest(ProvisioningBlockerSchema)
      .readonly(),
    kind: z.literal("blocked"),
    subject: AuthorityIdentitySchema,
  })
  .readonly();
export const DesiredProvisioningPlanSchema = z.union([
  GitHubProvisionPlanSchema,
  NonGitHubProvisionPlanSchema,
  DeprovisionPlanSchema,
  BlockedProvisioningPlanSchema,
]);

export type GoogleUserId = z.output<typeof GoogleUserIdSchema>;
export type GitHubUserId = z.output<typeof GitHubUserIdSchema>;
export type GitHubLogin = z.output<typeof GitHubLoginSchema>;
export type PrimaryEmail = z.output<typeof PrimaryEmailSchema>;
export type AuthorityRevision = z.output<typeof AuthorityRevisionSchema>;
export type ProvisioningIdempotencyKey = z.output<
  typeof ProvisioningIdempotencyKeySchema
>;
export type ProvisioningProviderId = z.output<
  typeof ProvisioningProviderIdSchema
>;
export type AuthorityIdentity = z.output<typeof AuthorityIdentitySchema>;
export type ProviderAccount = z.output<typeof ProviderAccountSchema>;
export type DesiredProvisioningPlan = z.output<
  typeof DesiredProvisioningPlanSchema
>;

function planIdempotencyKeyMatches(
  plan: {
    readonly idempotencyKey: ProvisioningIdempotencyKey;
    readonly subject: { readonly googleUserId: GoogleUserId };
    readonly target: { readonly providerId: ProvisioningProviderId };
  },
  action: "deprovision" | "provision",
): boolean {
  return plan.idempotencyKey.startsWith(
    `identity:v1:${plan.subject.googleUserId}:${plan.target.providerId}:${action}:`,
  );
}
const AuthorityDigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);

export function provisioningIdempotencyKey(input: {
  readonly action: "deprovision" | "provision";
  readonly authorityDigest: string;
  readonly googleUserId: GoogleUserId;
  readonly providerId: ProvisioningProviderId;
}): ProvisioningIdempotencyKey {
  const digest = AuthorityDigestSchema.parse(input.authorityDigest);
  return ProvisioningIdempotencyKeySchema.parse(
    `identity:v1:${input.googleUserId}:${input.providerId}:${input.action}:${digest}`,
  );
}
