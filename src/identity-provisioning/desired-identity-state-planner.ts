import {
  ActiveAuthorityIdentitySchema,
  type AuthorityIdentity,
  DesiredProvisioningPlanSchema,
  InactiveAuthorityIdentitySchema,
  type ProviderAccount,
  provisioningIdempotencyKey,
} from "../catalog/identity-authority.ts";
import { sha256 } from "../runtime/sha256.ts";
import type {
  IdentityProviderPlanner,
  IdentityProviderPlanningContext,
  ProviderObservation,
  ProviderPlanningDecision,
} from "./contracts.ts";
import {
  hasCompleteEmployeeEntitlementAuthority,
  isEmployeeEntitlementExcluded,
} from "./employee-entitlement-policy.ts";
import { protectedIdentityBlocker } from "./protected-identity-blocker.ts";

export class DesiredIdentityStatePlanner implements IdentityProviderPlanner {
  async plan(
    subject: AuthorityIdentity,
    observation: ProviderObservation,
    context?: IdentityProviderPlanningContext,
  ): Promise<ProviderPlanningDecision> {
    // Verified absence needs no provider mutation, including when deleted Google metadata is sparse.
    if (subject.lifecycle.kind !== "active" && observation.kind === "absent") {
      return { kind: "satisfied", providerId: observation.providerId, subject };
    }
    const protection = protectedIdentityBlocker(subject);
    if (protection !== undefined)
      return blocked(subject, "safety-policy", protection);
    const activeSubject = ActiveAuthorityIdentitySchema.safeParse(subject);
    if (activeSubject.success) {
      const exclusion = activeIdentityPolicyDecision(
        activeSubject.data,
        observation,
        context?.employeeEntitlementAuthority,
      );
      if (exclusion) return exclusion;
      if (observation.kind === "ambiguous") {
        return blocked(
          activeSubject.data,
          "provider-ambiguous",
          "Multiple provider accounts match the subject",
        );
      }
      if (observation.kind === "unsupported") {
        return blocked(
          activeSubject.data,
          "provider-unsupported",
          observation.detail,
        );
      }
      const targetResult = activeTarget(activeSubject.data, observation);
      if (targetResult.kind === "blocked") return targetResult.decision;
      const target = targetResult.target;
      if (observedTargetMatches(observation, target)) {
        return {
          kind: "satisfied",
          providerId: observation.providerId,
          subject: activeSubject.data,
        };
      }
      return DesiredProvisioningPlanSchema.parse({
        idempotencyKey: provisioningIdempotencyKey({
          action: "provision",
          authorityDigest: await desiredStateHash(
            activeSubject.data,
            target,
            context?.employeeEntitlementAuthority.fingerprint,
          ),
          googleUserId: activeSubject.data.googleUserId,
          providerId: observation.providerId,
        }),
        kind: "provision",
        subject: activeSubject.data,
        target,
      });
    }

    return inactiveIdentityDecision(subject, observation, context);
  }
}

async function inactiveIdentityDecision(
  subject: AuthorityIdentity,
  observation: ProviderObservation,
  context: IdentityProviderPlanningContext | undefined,
): Promise<ProviderPlanningDecision> {
  const inactiveSubject = InactiveAuthorityIdentitySchema.parse(subject);
  if (observation.kind === "ambiguous") {
    return blocked(
      inactiveSubject,
      "provider-ambiguous",
      "Multiple provider accounts match the subject",
    );
  }
  if (observation.kind === "unsupported") {
    return blocked(inactiveSubject, "provider-unsupported", observation.detail);
  }
  if (observation.kind === "absent") {
    return {
      kind: "satisfied",
      providerId: observation.providerId,
      subject: inactiveSubject,
    };
  }
  return DesiredProvisioningPlanSchema.parse({
    idempotencyKey: provisioningIdempotencyKey({
      action: "deprovision",
      authorityDigest: await desiredStateHash(
        inactiveSubject,
        observation.account,
        context?.employeeEntitlementAuthority.fingerprint,
      ),
      googleUserId: inactiveSubject.googleUserId,
      providerId: observation.providerId,
    }),
    kind: "deprovision",
    subject: inactiveSubject,
    target: observation.account,
  });
}

function activeIdentityPolicyDecision(
  subject: Extract<AuthorityIdentity, { lifecycle: { kind: "active" } }>,
  observation: ProviderObservation,
  authority?: IdentityProviderPlanningContext["employeeEntitlementAuthority"],
): ProviderPlanningDecision | undefined {
  if (
    !isEmployeeEntitlementExcluded(
      subject.primaryEmail,
      subject.googleUserId,
      authority,
      subject.aliases,
    )
  ) {
    if (hasCompleteEmployeeEntitlementAuthority(authority)) return;
    return blocked(
      subject,
      "safety-policy",
      "Complete current contractor authority is required for employee provisioning",
    );
  }
  if (observation.kind === "absent") {
    return { kind: "satisfied", providerId: observation.providerId, subject };
  }
  return blocked(
    subject,
    "safety-policy",
    "Contractor is ineligible for automatic employee-only provisioning; existing access requires review",
  );
}

function observedTargetMatches(
  observation: ProviderObservation,
  target: ProviderAccount,
): boolean {
  return (
    observation.kind === "present" &&
    sameProviderAccount(observation.account, target)
  );
}

function sameProviderAccount(
  left: ProviderAccount,
  right: ProviderAccount,
): boolean {
  if (left.providerId !== right.providerId) return false;
  if (left.providerId === "github" && right.providerId === "github") {
    return (
      left.githubUserId === right.githubUserId &&
      left.githubLogin === right.githubLogin
    );
  }
  return (
    left.providerId !== "github" &&
    right.providerId !== "github" &&
    left.accountId === right.accountId
  );
}

function activeTarget(
  subject: Extract<AuthorityIdentity, { lifecycle: { kind: "active" } }>,
  observation: Exclude<
    ProviderObservation,
    { kind: "ambiguous" | "unsupported" }
  >,
):
  | {
      readonly decision: Extract<ProviderPlanningDecision, { kind: "blocked" }>;
      readonly kind: "blocked";
    }
  | { readonly kind: "target"; readonly target: ProviderAccount } {
  if (observation.providerId === "github") {
    if (subject.github.kind === "unlinked") {
      return {
        decision: blocked(
          subject,
          "identity-unlinked",
          "Google authority has no verified GitHub identity",
        ),
        kind: "blocked",
      };
    }
    if (subject.github.kind === "conflict") {
      return {
        decision: blocked(
          subject,
          "authority-conflict",
          "Google authority has conflicting GitHub identity data",
        ),
        kind: "blocked",
      };
    }
    const target = {
      githubLogin: subject.github.githubLogin,
      githubUserId: subject.github.githubUserId,
      providerId: "github" as const,
    };
    if (
      observation.kind === "present" &&
      (observation.account.providerId !== "github" ||
        observation.account.githubUserId !== target.githubUserId ||
        observation.account.githubLogin !== target.githubLogin)
    ) {
      return {
        decision: blocked(
          subject,
          "provider-ambiguous",
          "GitHub account differs from verified authority",
        ),
        kind: "blocked",
      };
    }
    return { kind: "target", target };
  }
  if (observation.kind === "absent") {
    return {
      decision: blocked(
        subject,
        "provider-unsupported",
        `Provider ${observation.providerId} cannot derive an account target from Google authority`,
      ),
      kind: "blocked",
    };
  }
  if (observation.account.providerId !== observation.providerId) {
    return {
      decision: blocked(
        subject,
        "provider-ambiguous",
        "Observed account belongs to another provider",
      ),
      kind: "blocked",
    };
  }
  return { kind: "target", target: observation.account };
}

function blocked(
  subject: AuthorityIdentity,
  code:
    | "authority-conflict"
    | "identity-unlinked"
    | "provider-ambiguous"
    | "provider-unsupported"
    | "safety-policy",
  detail: string,
): Extract<ProviderPlanningDecision, { kind: "blocked" }> {
  const result = DesiredProvisioningPlanSchema.parse({
    blockers: [{ code, detail }],
    kind: "blocked",
    subject,
  });
  if (result.kind !== "blocked") throw new Error("blocked_plan_parse_failed");
  return result;
}

async function desiredStateHash(
  subject: AuthorityIdentity,
  target: ProviderAccount,
  employeeEntitlementFingerprint?: string,
): Promise<string> {
  const canonical = JSON.stringify({
    aliases: subject.aliases,
    authorityRevision: subject.authorityRevision,
    employeeEntitlementFingerprint,
    googleUserId: subject.googleUserId,
    isAdmin: subject.isAdmin,
    isDelegatedAdmin: subject.isDelegatedAdmin,
    lifecycle: subject.lifecycle.kind,
    target,
  });
  return sha256(canonical);
}
