import { dequal } from "dequal";
import { z } from "zod";

import {
  ActiveVerifiedAuthorityIdentitySchema,
  GitHubLoginSchema,
  GitHubUserIdSchema,
  GoogleUserIdSchema,
  InactiveAuthorityIdentitySchema,
  PrimaryEmailSchema,
  ProvisioningIdempotencyKeySchema,
} from "../catalog/identity-authority.ts";
import { matchesReviewedGitHubDirectGrants } from "../github-access-audit/reviewed-direct-grants.ts";
import type { GithubDispatchClaim } from "./github-zero-dispatch.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "./identity-budget-contracts.ts";
import { protectedIdentityBlocker } from "./protected-identity-blocker.ts";

const IsoInstantSchema = z.iso.datetime({ offset: true });
const GitHubInvitationIdSchema = z
  .number()
  .int()
  .positive()
  .brand<"GitHubInvitationId">();
const GitHubTeamIdSchema = z.number().int().positive().brand<"GitHubTeamId">();
const GitHubRepositoryIdSchema = z
  .number()
  .int()
  .positive()
  .brand<"GitHubRepositoryId">();
const GitHubTeamSlugSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u)
  .brand<"GitHubTeamSlug">();
const GitHubRepositoryNameSchema = z
  .string()
  .min(1)
  .regex(/^[^/]+\/[^/]+$/u)
  .brand<"GitHubRepositoryName">();

const GitHubAccountKeyShape = {
  githubLogin: GitHubLoginSchema,
  githubUserId: GitHubUserIdSchema,
} as const;

export const GitHubOrganizationMembershipSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    role: z.enum(["member", "owner"]),
  })
  .readonly();

export const GitHubPendingInvitationSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    invitationId: GitHubInvitationIdSchema,
    role: z.enum(["admin", "billing_manager", "direct_member"]),
  })
  .readonly();

export const GitHubTeamMembershipSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    inherited: z.boolean(),
    role: z.enum(["maintainer", "member"]),
    state: z.enum(["active", "pending"]),
    teamId: GitHubTeamIdSchema,
    teamSlug: GitHubTeamSlugSchema,
  })
  .readonly();

export const GitHubDirectRepositoryGrantSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    customRoleName: z.string().min(1).optional(),
    unresolvedDirectRole: z.literal(true).optional(),
    permission: z.enum(["admin", "maintain", "pull", "push", "triage"]),
    repositoryId: GitHubRepositoryIdSchema,
    repositoryName: GitHubRepositoryNameSchema,
  })
  .readonly();

export const GitHubObservedOrganizationAccountSchema = z
  .strictObject({
    complete: z.literal(true),
    directRepositoryGrants: z
      .array(GitHubDirectRepositoryGrantSchema)
      .readonly(),
    identity: z.strictObject(GitHubAccountKeyShape).readonly(),
    membership: GitHubOrganizationMembershipSchema.nullable(),
    observedAt: IsoInstantSchema,
    outsideCollaborator: z.boolean(),
    pendingInvitations: z.array(GitHubPendingInvitationSchema).readonly(),
    unresolvedInvitations: z
      .enum(["opaque-direct", "identity-or-privilege"])
      .optional(),
    repositoryInventoryComplete: z.boolean(),
    samlLinked: z.boolean(),
    teamMemberships: z.array(GitHubTeamMembershipSchema).readonly(),
  })
  .superRefine((snapshot, context) =>
    validateObservedAccount(snapshot, context),
  )
  .readonly();

export const ReviewedDirectGrantRetentionSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    allowedTeamSlugs: z.array(GitHubTeamSlugSchema).min(1).readonly(),
    googleUserId: GoogleUserIdSchema,
    grants: z
      .array(
        GitHubDirectRepositoryGrantSchema.unwrap().omit({
          githubLogin: true,
          githubUserId: true,
          unresolvedDirectRole: true,
        }),
      )
      .min(1)
      .readonly(),
    primaryEmail: PrimaryEmailSchema,
    reviewedAt: z.iso.date(),
  })
  .superRefine((reviewed, context) => {
    addDuplicateIssues(reviewed.allowedTeamSlugs, "allowedTeamSlugs", context);
    addDuplicateIssues(
      reviewed.grants.map(({ repositoryId }) => repositoryId),
      "grants",
      context,
    );
  })
  .readonly();

const DesiredPresentSchema = z
  .strictObject({
    desiredTeamSlugs: z.array(GitHubTeamSlugSchema).readonly(),
    idempotencyKey: ProvisioningIdempotencyKeySchema,
    kind: z.literal("present"),
    managedTeamSlugs: z.array(GitHubTeamSlugSchema).min(1).readonly(),
    organizationRole: z.literal("member"),
    rehirePolicy: z.literal("fresh-least-privilege"),
    reviewedDirectGrantRetention: ReviewedDirectGrantRetentionSchema.optional(),
    subject: ActiveVerifiedAuthorityIdentitySchema,
  })
  .superRefine((desired, context) => {
    if (
      !desired.idempotencyKey.startsWith(
        `identity:v1:${desired.subject.googleUserId}:github:provision:`,
      )
    ) {
      context.addIssue({
        code: "custom",
        message:
          "GitHub presence requires a provision key bound to the immutable Google subject",
        path: ["idempotencyKey"],
      });
    }
    addDuplicateIssues(desired.desiredTeamSlugs, "desiredTeamSlugs", context);
    addDuplicateIssues(desired.managedTeamSlugs, "managedTeamSlugs", context);
    const managed = new Set(desired.managedTeamSlugs);
    for (const [index, teamSlug] of desired.desiredTeamSlugs.entries()) {
      if (!managed.has(teamSlug)) {
        context.addIssue({
          code: "custom",
          message:
            "Every desired team must be inside the explicit managed-team boundary",
          path: ["desiredTeamSlugs", index],
        });
      }
    }
  })
  .readonly();

const DesiredAbsentSchema = z
  .strictObject({
    idempotencyKey: ProvisioningIdempotencyKeySchema,
    kind: z.literal("absent"),
    subject: InactiveAuthorityIdentitySchema,
    target: z.strictObject(GitHubAccountKeyShape).readonly(),
  })
  .superRefine((desired, context) => {
    if (
      !desired.idempotencyKey.startsWith(
        `identity:v1:${desired.subject.googleUserId}:github:deprovision:`,
      )
    ) {
      context.addIssue({
        code: "custom",
        message:
          "GitHub absence requires a deprovision key bound to the immutable Google subject",
        path: ["idempotencyKey"],
      });
    }
  })
  .readonly();

export const GitHubDesiredOrganizationAccessSchema = z.discriminatedUnion(
  "kind",
  [DesiredPresentSchema, DesiredAbsentSchema],
);

const InviteMemberOperationSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    kind: z.literal("invite-organization-member"),
    role: z.literal("member"),
  })
  .readonly();
const CancelInvitationOperationSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    invitationId: GitHubInvitationIdSchema,
    kind: z.literal("cancel-invitation"),
  })
  .readonly();
const RemoveMemberOperationSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    kind: z.literal("remove-organization-member"),
  })
  .readonly();
const AddTeamMemberOperationSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    kind: z.literal("add-team-member"),
    role: z.literal("member"),
    teamSlug: GitHubTeamSlugSchema,
  })
  .readonly();
const RemoveTeamMemberOperationSchema = z
  .strictObject({
    ...GitHubAccountKeyShape,
    kind: z.literal("remove-team-member"),
    teamSlug: GitHubTeamSlugSchema,
  })
  .readonly();

export const GitHubProvisioningOperationSchema = z.discriminatedUnion("kind", [
  InviteMemberOperationSchema,
  CancelInvitationOperationSchema,
  RemoveMemberOperationSchema,
  AddTeamMemberOperationSchema,
  RemoveTeamMemberOperationSchema,
]);
const GitHubProvisioningOperationKindSchema = z.enum([
  "invite-organization-member",
  "cancel-invitation",
  "remove-organization-member",
  "add-team-member",
  "remove-team-member",
]);

export const GitHubProvisioningBlockerCodeSchema = z.enum([
  "direct-repository-grants",
  "identity-mismatch",
  "team-maintainer",
  "inherited-team-membership",
  "pending-invitation",
  "pending-team-membership",
  "repository-inventory-incomplete",
  "saml-unlinked",
  "outside-collaborator",
  "owner-protected",
  "privileged-invitation",
  "protected-google-identity",
]);
export const GitHubProvisioningBlockerSchema = z
  .strictObject({
    code: GitHubProvisioningBlockerCodeSchema,
    detail: z.string().min(1),
  })
  .readonly();

const GitHubExecutablePlanSchema = z
  .strictObject({
    desired: GitHubDesiredOrganizationAccessSchema,
    kind: z.literal("executable"),
    observedAt: IsoInstantSchema,
    operations: z.array(GitHubProvisioningOperationSchema).readonly(),
  })
  .readonly();
const GitHubBlockedPlanSchema = z
  .strictObject({
    blockers: z
      .tuple([GitHubProvisioningBlockerSchema])
      .rest(GitHubProvisioningBlockerSchema),
    desired: GitHubDesiredOrganizationAccessSchema,
    kind: z.literal("blocked"),
    observedAt: IsoInstantSchema,
  })
  .readonly();
export const GitHubOrganizationProvisioningPlanSchema = z.discriminatedUnion(
  "kind",
  [GitHubExecutablePlanSchema, GitHubBlockedPlanSchema],
);
const GitHubInvitationAccessStateSchema = z.enum([
  "active-member",
  "pending-acceptance",
]);
const GITHUB_PENDING_INVITATION_DETAIL =
  "Invitation is awaiting acceptance and must not be reported as converged access";

export const GitHubMutationReceiptSchema = z.discriminatedUnion("state", [
  z
    .strictObject({
      kind: GitHubProvisioningOperationKindSchema,
      state: z.literal("converged"),
    })
    .readonly(),
  z
    .strictObject({
      access: GitHubInvitationAccessStateSchema,
      kind: z.literal("invite-organization-member"),
      state: z.literal("invited"),
    })
    .readonly(),
]);

export type GitHubObservedOrganizationAccount = z.output<
  typeof GitHubObservedOrganizationAccountSchema
>;
export type GitHubDesiredOrganizationAccess = z.output<
  typeof GitHubDesiredOrganizationAccessSchema
>;
export type GitHubProvisioningOperation = z.output<
  typeof GitHubProvisioningOperationSchema
>;
export type GitHubOrganizationProvisioningPlan = z.output<
  typeof GitHubOrganizationProvisioningPlanSchema
>;

interface GitHubOrganizationReadCapability {
  observeAccount(input: {
    readonly githubLogin: z.output<typeof GitHubLoginSchema>;
    readonly githubUserId: z.output<typeof GitHubUserIdSchema>;
    readonly primaryEmail: string;
  }): Promise<unknown>;
}

export interface ReadOnlyGitHubOrganizationPort extends GitHubOrganizationReadCapability {
  readonly capability: "read-only";
}

/* Exposes only the observation capability, even when the underlying adapter can mutate. */
export function readOnlyGitHubOrganizationPort(
  port: GitHubOrganizationReadCapability,
): ReadOnlyGitHubOrganizationPort {
  return {
    capability: "read-only",
    observeAccount: port.observeAccount.bind(port),
  };
}

export interface MutatingGitHubOrganizationPort extends GitHubOrganizationReadCapability {
  readonly capability: "mutating";
  execute(
    operation: GitHubProvisioningOperation,
    assertFinalWriteAuthority?: () => Promise<void>,
    dispatchClaim?: GithubDispatchClaim,
  ): Promise<unknown>;
  verifyWriterTenant?(): Promise<void>;
}

export interface GitHubOrganizationWriteContext {
  assertFreshPlan(): void;
  assertWriteAuthority(operation: GitHubProvisioningOperation): Promise<void>;
  githubDispatchClaim?: GithubDispatchClaim;
}

export type GitHubOrganizationPort =
  | MutatingGitHubOrganizationPort
  | ReadOnlyGitHubOrganizationPort;

export interface GitHubOrganizationPlanningService {
  plan(rawDesired: unknown): Promise<GitHubOrganizationProvisioningPlan>;
}

export class DryRunGitHubOrganizationConnector implements GitHubOrganizationPlanningService {
  readonly #port: ReadOnlyGitHubOrganizationPort;

  constructor(port: ReadOnlyGitHubOrganizationPort) {
    this.#port = port;
  }

  async plan(rawDesired: unknown): Promise<GitHubOrganizationProvisioningPlan> {
    const desired = GitHubDesiredOrganizationAccessSchema.parse(rawDesired);
    const identity = desiredIdentity(desired);
    const observed = GitHubObservedOrganizationAccountSchema.parse(
      await this.#port.observeAccount(identity),
    );
    return planGitHubOrganizationAccess(desired, observed);
  }
}

export function planGitHubOrganizationAccess(
  rawDesired: unknown,
  rawObserved: unknown,
): GitHubOrganizationProvisioningPlan {
  const desired = GitHubDesiredOrganizationAccessSchema.parse(rawDesired);
  const observed = GitHubObservedOrganizationAccountSchema.parse(rawObserved);
  const expectedIdentity = desiredIdentity(desired);
  const operations =
    desired.kind === "absent"
      ? planAbsence(desired, observed)
      : planPresence(desired, observed);
  const blockers = provisioningBlockers(
    desired,
    observed,
    expectedIdentity,
    operations,
  );
  const protection = protectedIdentityBlocker(desired.subject);
  if (protection !== undefined) {
    blockers.push({ code: "protected-google-identity", detail: protection });
  }
  if (blockers.length > 0) {
    return GitHubOrganizationProvisioningPlanSchema.parse({
      blockers,
      desired,
      kind: "blocked",
      observedAt: observed.observedAt,
    });
  }
  return GitHubOrganizationProvisioningPlanSchema.parse({
    desired,
    kind: "executable",
    observedAt: observed.observedAt,
    operations,
  });
}

export async function executeGitHubOrganizationPlan(
  port: GitHubOrganizationPort,
  rawPlan: unknown,
  refreshDesired: GitHubDesiredAuthorityRefresh,
  identityBudget?: IdentityWriteBudget,
): Promise<readonly z.output<typeof GitHubMutationReceiptSchema>[]> {
  if (port.capability !== "mutating") {
    throw new GitHubMutationCapabilityError();
  }
  const plan = GitHubOrganizationProvisioningPlanSchema.parse(rawPlan);
  if (plan.kind === "blocked") throw new GitHubBlockedPlanError();
  const current = GitHubObservedOrganizationAccountSchema.parse(
    await port.observeAccount(desiredIdentity(plan.desired)),
  );
  const currentPlan = planGitHubOrganizationAccess(plan.desired, current);
  if (currentPlan.kind === "blocked") throw new GitHubBlockedPlanError();
  const approvedOperations = new Set(
    plan.operations.map((operation) => JSON.stringify(operation)),
  );
  if (
    currentPlan.operations.some(
      (operation) => !approvedOperations.has(JSON.stringify(operation)),
    )
  ) {
    throw new GitHubPlanDriftError();
  }
  const receipts: z.output<typeof GitHubMutationReceiptSchema>[] = [];
  for (const operation of currentPlan.operations) {
    // eslint-disable-next-line no-await-in-loop -- Refresh sole lifecycle authority before every ordered write.
    await assertFreshDesiredAuthority(plan.desired, refreshDesired);
    // eslint-disable-next-line no-await-in-loop -- Every ordered mutation consumes the same immutable subject reservation.
    await reserveIdentityWriteBudget(
      identityBudget,
      plan.desired.subject.googleUserId,
    );
    // eslint-disable-next-line no-await-in-loop -- Reservation persistence must not outlive the final authority check.
    await assertFreshDesiredAuthority(plan.desired, refreshDesired);
    const receipt = GitHubMutationReceiptSchema.parse(
      // eslint-disable-next-line no-await-in-loop -- Ordered mutations preserve least-privilege transitions.
      await port.execute(operation, () =>
        assertFreshDesiredAuthority(plan.desired, refreshDesired),
      ),
    );
    if (receipt.kind !== operation.kind)
      throw new GitHubMutationReceiptMismatchError();
    receipts.push(receipt);
  }
  return receipts;
}

/* Executes one explicitly selected operation after a fresh authoritative re-plan. */
export async function executeGitHubOrganizationOperation(
  port: GitHubOrganizationPort,
  rawDesired: unknown,
  rawSelectedOperation: unknown,
  refreshDesired: GitHubDesiredAuthorityRefresh,
  identityBudget?: IdentityWriteBudget,
  writeContext?: GitHubOrganizationWriteContext,
): Promise<z.output<typeof GitHubMutationReceiptSchema>> {
  if (port.capability !== "mutating") throw new GitHubMutationCapabilityError();
  const desired = GitHubDesiredOrganizationAccessSchema.parse(rawDesired);
  const selectedOperation =
    GitHubProvisioningOperationSchema.parse(rawSelectedOperation);
  const observed = GitHubObservedOrganizationAccountSchema.parse(
    await port.observeAccount(desiredIdentity(desired)),
  );
  const currentPlan = planGitHubOrganizationAccess(desired, observed);
  if (currentPlan.kind === "blocked") throw new GitHubBlockedPlanError();
  if (!dequal(currentPlan.operations[0], selectedOperation)) {
    throw new GitHubPlanDriftError();
  }
  await assertFreshDesiredAuthority(desired, refreshDesired);
  assertGithubParentContext(identityBudget, writeContext);
  await reserveIdentityWriteBudget(
    identityBudget,
    desired.subject.googleUserId,
  );
  await assertFreshDesiredAuthority(desired, refreshDesired);
  const receipt = GitHubMutationReceiptSchema.parse(
    await port.execute(
      selectedOperation,
      async () => {
        await writeContext?.assertWriteAuthority(selectedOperation);
        await assertFreshDesiredAuthority(desired, refreshDesired);
        writeContext?.assertFreshPlan();
      },
      writeContext?.githubDispatchClaim,
    ),
  );
  if (receipt.kind !== selectedOperation.kind)
    throw new GitHubMutationReceiptMismatchError();
  return receipt;
}

function assertGithubParentContext(
  budget: IdentityWriteBudget | undefined,
  context: GitHubOrganizationWriteContext | undefined,
): void {
  if (budget?.required === true && context === undefined)
    throw new Error("github_original_parent_context_required");
  if (context !== undefined && budget?.required !== true)
    throw new Error("github_original_parent_budget_required");
}

/** Re-capture complete Google and contractor authority; absence must return null, never offboard. */
export type GitHubDesiredAuthorityRefresh = (
  googleUserId: string,
) => Promise<unknown>;

async function assertFreshDesiredAuthority(
  desired: GitHubDesiredOrganizationAccess,
  refreshDesired: GitHubDesiredAuthorityRefresh,
): Promise<void> {
  const fresh = GitHubDesiredOrganizationAccessSchema.safeParse(
    await refreshDesired(desired.subject.googleUserId),
  );
  if (
    !fresh.success ||
    protectedIdentityBlocker(fresh.data.subject) !== undefined ||
    !sameGitHubDesiredAuthority(fresh.data, desired)
  ) {
    throw new GitHubPlanDriftError();
  }
}

// Capture metadata and its derived idempotency key change on every observation.
export function sameGitHubDesiredAuthority(
  current: GitHubDesiredOrganizationAccess,
  expected: GitHubDesiredOrganizationAccess,
): boolean {
  return dequal(
    stableAuthorityDesired(current),
    stableAuthorityDesired(expected),
  );
}

function stableAuthorityDesired(desired: GitHubDesiredOrganizationAccess) {
  return {
    ...desired,
    idempotencyKey: undefined,
    subject: {
      ...desired.subject,
      authorityRevision: undefined,
      observedAt: undefined,
      github:
        desired.subject.github.kind === "verified"
          ? { ...desired.subject.github, verifiedAt: undefined }
          : desired.subject.github,
    },
  };
}

export class GitHubMutationCapabilityError extends Error {
  constructor() {
    super("github_mutation_capability_required");
    this.name = "GitHubMutationCapabilityError";
  }
}

export class GitHubBlockedPlanError extends Error {
  constructor() {
    super("github_blocked_plan_cannot_execute");
    this.name = "GitHubBlockedPlanError";
  }
}

export class GitHubPlanDriftError extends Error {
  constructor() {
    super("github_plan_changed_after_approval");
    this.name = "GitHubPlanDriftError";
  }
}

export class GitHubMutationReceiptMismatchError extends Error {
  constructor() {
    super("github_mutation_receipt_mismatch");
    this.name = "GitHubMutationReceiptMismatchError";
  }
}

function desiredIdentity(desired: GitHubDesiredOrganizationAccess) {
  return desired.kind === "present"
    ? {
        githubLogin: desired.subject.github.githubLogin,
        githubUserId: desired.subject.github.githubUserId,
        primaryEmail: desired.subject.primaryEmail,
      }
    : { ...desired.target, primaryEmail: desired.subject.primaryEmail };
}

function provisioningBlockers(
  desired: GitHubDesiredOrganizationAccess,
  observed: GitHubObservedOrganizationAccount,
  expectedIdentity: ReturnType<typeof desiredIdentity>,
  operations: readonly GitHubProvisioningOperation[],
) {
  const blockers: z.output<typeof GitHubProvisioningBlockerSchema>[] = [];
  if (
    observed.identity.githubUserId !== expectedIdentity.githubUserId ||
    observed.identity.githubLogin !== expectedIdentity.githubLogin
  ) {
    blockers.push({
      code: "identity-mismatch",
      detail:
        "Observed GitHub ID and login do not match the verified authority identity",
    });
  }
  if (
    observed.unresolvedInvitations &&
    !(
      observed.unresolvedInvitations === "opaque-direct" &&
      observed.membership?.role === "member" &&
      desired.kind === "present" &&
      operations.every((operation) => operation.kind === "add-team-member")
    )
  ) {
    blockers.push({
      code: "pending-invitation",
      detail: "Invitation identity could not be established",
    });
  }
  if (observed.membership?.role === "owner") {
    blockers.push({
      code: "owner-protected",
      detail: "Organization owners require manual review",
    });
  }
  if (
    observed.pendingInvitations.some(
      (invitation) => invitation.role !== "direct_member",
    )
  ) {
    blockers.push({
      code: "privileged-invitation",
      detail:
        "An owner, administrator, or billing-manager invitation requires manual review",
    });
  }
  if (desired.kind === "present" && observed.pendingInvitations.length > 0) {
    blockers.push({
      code: "pending-invitation",
      detail: GITHUB_PENDING_INVITATION_DETAIL,
    });
  }
  blockers.push(
    ...legacyAccessBlockers(desired, observed, operations),
    ...pendingTeamBlockers(desired, observed),
  );
  if (observed.outsideCollaborator) {
    blockers.push({
      code: "outside-collaborator",
      detail:
        "Outside-collaborator access requires manual review before membership reconciliation",
    });
  }
  if (
    desired.kind === "present" &&
    observed.membership !== null &&
    !observed.samlLinked
  ) {
    blockers.push({
      code: "saml-unlinked",
      detail:
        "Active organization member must have a linked SAML identity before team changes",
    });
  }
  if (!observed.repositoryInventoryComplete) {
    blockers.push({
      code: "repository-inventory-incomplete",
      detail:
        "GitHub access reconciliation requires complete all-repository coverage",
    });
  }
  if (
    desired.kind === "present" &&
    observed.teamMemberships.some(
      (membership) =>
        membership.inherited &&
        desired.managedTeamSlugs.includes(membership.teamSlug) &&
        !desired.desiredTeamSlugs.includes(membership.teamSlug),
    )
  ) {
    blockers.push({
      code: "inherited-team-membership",
      detail:
        "Inherited membership cannot be removed directly from the parent team",
    });
  }
  return blockers;
}

function pendingTeamBlockers(
  desired: GitHubDesiredOrganizationAccess,
  observed: GitHubObservedOrganizationAccount,
): z.output<typeof GitHubProvisioningBlockerSchema>[] {
  if (desired.kind !== "present") return [];
  const waiting = observed.teamMemberships.some(
    (membership) =>
      membership.state === "pending" &&
      desired.desiredTeamSlugs.includes(membership.teamSlug),
  );
  return waiting
    ? [
        {
          code: "pending-team-membership",
          detail:
            "Desired team membership is pending; wait for active access before reconciliation",
        },
      ]
    : [];
}

function legacyAccessBlockers(
  desired: GitHubDesiredOrganizationAccess,
  observed: GitHubObservedOrganizationAccount,
  operations: readonly GitHubProvisioningOperation[],
): z.output<typeof GitHubProvisioningBlockerSchema>[] {
  const nextOperation = operations[0];
  if (nextOperation === undefined) return [];
  const reviewed =
    desired.kind === "present"
      ? desired.reviewedDirectGrantRetention
      : undefined;
  const retainedForAdditions =
    desired.kind === "present" &&
    reviewed !== undefined &&
    observed.membership?.role === "member" &&
    operations.every(
      (operation) =>
        operation.kind === "add-team-member" &&
        reviewed.allowedTeamSlugs.includes(operation.teamSlug),
    ) &&
    matchesReviewedGitHubDirectGrants(
      reviewed,
      {
        ...desired.subject.github,
        googleUserId: desired.subject.googleUserId,
        primaryEmail: desired.subject.primaryEmail,
      },
      observed.directRepositoryGrants,
    );
  return [
    ...((observed.directRepositoryGrants.length === 0 &&
      reviewed === undefined) ||
    retainedForAdditions
      ? []
      : [
          {
            code: "direct-repository-grants" as const,
            detail:
              "Direct repository grants require an exact retention review before additive team access; other access changes remain blocked",
          },
        ]),
    ...(observed.teamMemberships.some(
      (membership) => membership.role === "maintainer",
    )
      ? [
          {
            code: "team-maintainer" as const,
            detail:
              "Team maintainers require explicit manual review before access changes",
          },
        ]
      : []),
  ];
}

function planPresence(
  desired: z.output<typeof DesiredPresentSchema>,
  observed: GitHubObservedOrganizationAccount,
): readonly GitHubProvisioningOperation[] {
  const login = desired.subject.github.githubLogin;
  if (observed.membership === null) {
    if (observed.pendingInvitations.length > 0) return [];
    return [
      {
        githubLogin: login,
        githubUserId: desired.subject.github.githubUserId,
        kind: "invite-organization-member",
        role: "member",
      },
    ];
  }
  const desiredTeams = new Set(desired.desiredTeamSlugs);
  const managedTeams = new Set(desired.managedTeamSlugs);
  const currentTeams = new Set(
    observed.teamMemberships
      .filter(
        (membership) =>
          membership.state === "active" &&
          managedTeams.has(membership.teamSlug),
      )
      .map((membership) => membership.teamSlug),
  );
  return [
    ...[...desiredTeams]
      .filter((teamSlug) => !currentTeams.has(teamSlug))
      .toSorted((left, right) => left.localeCompare(right))
      .map((teamSlug) => ({
        githubLogin: login,
        githubUserId: desired.subject.github.githubUserId,
        kind: "add-team-member" as const,
        role: "member" as const,
        teamSlug,
      })),
    ...[...currentTeams]
      .filter((teamSlug) => !desiredTeams.has(teamSlug))
      .toSorted((left, right) => left.localeCompare(right))
      .map((teamSlug) => ({
        githubLogin: login,
        githubUserId: desired.subject.github.githubUserId,
        kind: "remove-team-member" as const,
        teamSlug,
      })),
  ];
}

function planAbsence(
  desired: z.output<typeof DesiredAbsentSchema>,
  observed: GitHubObservedOrganizationAccount,
): readonly GitHubProvisioningOperation[] {
  return [
    ...observed.pendingInvitations
      .toSorted((left, right) => left.invitationId - right.invitationId)
      .map((invitation) => ({
        githubLogin: invitation.githubLogin,
        githubUserId: invitation.githubUserId,
        invitationId: invitation.invitationId,
        kind: "cancel-invitation" as const,
      })),
    ...(observed.membership === null
      ? []
      : [
          {
            githubLogin: desired.target.githubLogin,
            githubUserId: desired.target.githubUserId,
            kind: "remove-organization-member" as const,
          },
        ]),
  ];
}

function validateObservedAccount(
  snapshot: {
    readonly directRepositoryGrants: readonly {
      githubLogin: string;
      githubUserId: string;
    }[];
    readonly identity: { githubLogin: string; githubUserId: string };
    readonly membership: { githubLogin: string; githubUserId: string } | null;
    readonly pendingInvitations: readonly {
      githubLogin: string;
      githubUserId: string;
      invitationId: number;
    }[];
    readonly teamMemberships: readonly {
      githubLogin: string;
      githubUserId: string;
      teamSlug: string;
    }[];
  },
  context: z.RefinementCtx,
): void {
  const accounts = [
    ...(snapshot.membership === null ? [] : [snapshot.membership]),
    ...snapshot.pendingInvitations,
    ...snapshot.teamMemberships,
    ...snapshot.directRepositoryGrants,
  ];
  for (const account of accounts) {
    if (
      account.githubUserId !== snapshot.identity.githubUserId ||
      account.githubLogin !== snapshot.identity.githubLogin
    ) {
      context.addIssue({
        code: "custom",
        message: "Every observation must match its account key",
      });
      break;
    }
  }
  addDuplicateIssues(
    snapshot.pendingInvitations.map((invitation) => invitation.invitationId),
    "pendingInvitations",
    context,
  );
  addDuplicateIssues(
    snapshot.teamMemberships.map((membership) => membership.teamSlug),
    "teamMemberships",
    context,
  );
}

function addDuplicateIssues(
  values: readonly (number | string)[],
  path: string,
  context: z.RefinementCtx,
): void {
  if (new Set(values).size !== values.length) {
    context.addIssue({
      code: "custom",
      message: `${path} must not contain duplicates`,
      path: [path],
    });
  }
}
