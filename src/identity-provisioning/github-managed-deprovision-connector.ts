import { z } from "zod";

import {
  type AuthorityIdentity,
  type DesiredProvisioningPlan,
  DesiredProvisioningPlanSchema,
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import { providerWrite } from "../runtime/provider-write.ts";
import { sha256 } from "../runtime/sha256.ts";
import type {
  IdentityProviderPlanner,
  IdentityProviderPlanningContext,
  ManagedIdentityProviderConnector,
  ProviderApplyReceipt,
  ProviderObservation,
  ProviderPlanningDecision,
  ProviderVerification,
} from "./contracts.ts";
import {
  identityProvisioningSha256,
  ProviderApplyReceiptSchema,
  providerLifecycleProtocol,
} from "./contracts.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "./identity-budget-contracts.ts";
import { protectedIdentityBlocker } from "./protected-identity-blocker.ts";

const GitHubOrganizationIdSchema = z
  .string()
  .regex(/^[1-9]\d*$/u)
  .brand<"GitHubOrganizationId">();
const GitHubOrganizationLoginSchema = z
  .string()
  .min(1)
  .max(39)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9]))*$/u)
  .transform((value) => value.toLowerCase())
  .brand<"GitHubOrganizationLogin">();
const GitHubOrganizationSchema = z.object({
  id: z.number().int().positive(),
  login: GitHubOrganizationLoginSchema,
});
const GitHubUserSchema = z.object({
  id: z.number().int().positive(),
  login: GitHubLoginSchema,
});
const GitHubMembershipSchema = z.object({
  role: z.enum(["admin", "member"]),
  state: z.enum(["active", "pending"]),
  user: GitHubUserSchema,
});
const GitHubInvitationSchema = z.object({
  id: z.number().int().positive(),
  login: GitHubLoginSchema.nullish(),
  email: z.email().nullish(),
  invitee: GitHubUserSchema.nullish(),
});
const GitHubManagedDeprovisionConfigSchema = z.strictObject({
  organizationId: GitHubOrganizationIdSchema,
  organizationLogin: GitHubOrganizationLoginSchema,
  token: z.string().min(1),
});

type ExecutablePlan = Exclude<DesiredProvisioningPlan, { kind: "blocked" }>;

export interface GitHubManagedDeprovisionConfig {
  readonly fetchImpl?: typeof fetch;
  readonly identityBudget?: IdentityWriteBudget;
  readonly organizationId: string;
  readonly organizationLogin: string;
  readonly planner: IdentityProviderPlanner;
  readonly readGoogleAuthority: (
    googleUserId: string,
  ) => Promise<AuthorityIdentity | null>;
  readonly token: string;
}

/**
 * A deliberately deprovision-only connector. Google Directory supplies the
 * immutable person-to-GitHub mapping; GitHub supplies only fresh observed state.
 */
export class GitHubManagedDeprovisionConnector implements ManagedIdentityProviderConnector {
  readonly protocol = providerLifecycleProtocol({
    authority: "google-workspace",
    execution: "managed",
    managedActions: ["deprovision"],
    providerId: "github",
    verification: "authoritative-readback",
  });
  readonly execution = "managed";
  readonly providerId = "github";
  readonly #fetchImpl: typeof fetch;
  readonly #organizationId: z.output<typeof GitHubOrganizationIdSchema>;
  readonly #organizationLogin: z.output<typeof GitHubOrganizationLoginSchema>;
  readonly #planner: IdentityProviderPlanner;
  readonly #token: string;
  readonly #identityBudget: IdentityWriteBudget | undefined;
  readonly #readGoogleAuthority: GitHubManagedDeprovisionConfig["readGoogleAuthority"];

  constructor(rawConfig: GitHubManagedDeprovisionConfig) {
    const config = GitHubManagedDeprovisionConfigSchema.parse({
      organizationId: rawConfig.organizationId,
      organizationLogin: rawConfig.organizationLogin,
      token: rawConfig.token,
    });
    this.#fetchImpl = fetchPort(rawConfig.fetchImpl ?? runtimeFetch);
    this.#organizationId = config.organizationId;
    this.#organizationLogin = config.organizationLogin;
    this.#planner = rawConfig.planner;
    this.#token = config.token;
    this.#identityBudget = rawConfig.identityBudget;
    this.#readGoogleAuthority = rawConfig.readGoogleAuthority;
  }

  async observe(subject: AuthorityIdentity): Promise<ProviderObservation> {
    await this.#assertOrganizationPin();
    if (subject.github.kind !== "verified") {
      return {
        detail: "Google authority has no verified immutable GitHub identity",
        kind: "unsupported",
        providerId: this.providerId,
      };
    }
    const expected = {
      githubLogin: subject.github.githubLogin,
      githubUserId: subject.github.githubUserId,
      providerId: this.providerId,
    } as const;
    const account = await this.#getUser(expected.githubLogin);
    if (
      account.githubLogin !== expected.githubLogin ||
      account.githubUserId !== expected.githubUserId
    ) {
      return {
        candidates: [account],
        kind: "ambiguous",
        providerId: this.providerId,
      };
    }
    const membership = await this.#getMembership(expected.githubLogin);
    if (membership === null) {
      const residual = await this.#residualAccess(subject);
      if (residual !== null) {
        return {
          kind: "unsupported",
          detail: residual,
          providerId: this.providerId,
        };
      }
      return { kind: "absent", providerId: this.providerId };
    }
    if (membership.role !== "member" && subject.lifecycle.kind !== "active")
      throw new GitHubUnsafeMutationError();
    if (
      membership.user.login !== expected.githubLogin ||
      String(membership.user.id) !== expected.githubUserId
    ) {
      return {
        candidates: [
          {
            githubLogin: membership.user.login,
            githubUserId: GitHubUserIdSchema.parse(String(membership.user.id)),
            providerId: this.providerId,
          },
        ],
        kind: "ambiguous",
        providerId: this.providerId,
      };
    }
    if (membership.role !== "member") {
      return {
        detail:
          "Active organization administrators are outside managed deprovisioning",
        kind: "unsupported",
        providerId: this.providerId,
      };
    }
    return { account: expected, kind: "present", providerId: this.providerId };
  }

  async plan(
    subject: AuthorityIdentity,
    observation: ProviderObservation,
    context?: IdentityProviderPlanningContext,
  ): Promise<ProviderPlanningDecision> {
    const decision = await this.#planner.plan(subject, observation, context);
    if (decision.kind !== "provision") return decision;
    return blocked(
      subject,
      "This managed connector never provisions or mutates active subjects",
    );
  }

  async apply(
    rawPlan: ExecutablePlan,
    beforeDispatch: () => Promise<void>,
  ): Promise<ProviderApplyReceipt> {
    const plan = DesiredProvisioningPlanSchema.parse(rawPlan);
    if (
      plan.kind !== "deprovision" ||
      plan.target.providerId !== this.providerId ||
      protectedIdentityBlocker(plan.subject) !== undefined
    )
      throw new GitHubUnsafeMutationError();
    if (!planMatchesAuthority(plan)) throw new GitHubIdentityMismatchError();
    const observation = await this.observe(plan.subject);
    if (observation.kind === "absent")
      return receiptFor(plan, this.#organizationId);
    if (
      observation.kind !== "present" ||
      observation.account.providerId !== this.providerId ||
      observation.account.githubLogin !== plan.target.githubLogin ||
      observation.account.githubUserId !== plan.target.githubUserId
    ) {
      throw new GitHubIdentityMismatchError();
    }

    return this.#removeMembership(plan, beforeDispatch);
  }

  async recover(plan: ExecutablePlan): Promise<ProviderVerification> {
    // Recovery is read-only. A timed-out DELETE does not authorize another write.
    if (plan.kind !== "deprovision")
      return { kind: "mismatch", errorCode: "github_unsafe_mutation" };
    return this.verify(plan, receiptFor(plan, this.#organizationId));
  }

  async verify(
    plan: ExecutablePlan,
    rawReceipt: ProviderApplyReceipt,
  ): Promise<ProviderVerification> {
    if (
      plan.kind !== "deprovision" ||
      plan.target.providerId !== this.providerId
    ) {
      return { errorCode: "github_unsafe_mutation", kind: "mismatch" };
    }
    if (!planMatchesAuthority(plan)) {
      return {
        errorCode: "github_authority_target_mismatch",
        kind: "mismatch",
      };
    }
    const receipt = ProviderApplyReceiptSchema.parse(rawReceipt);
    if (
      receipt.idempotencyKey !== plan.idempotencyKey ||
      receipt.providerReceiptId !==
        providerReceiptId(plan, this.#organizationId)
    ) {
      return { errorCode: "github_receipt_mismatch", kind: "mismatch" };
    }
    const observation = await this.observe(plan.subject);
    if (observation.kind !== "absent") {
      return {
        errorCode: "github_deprovision_readback_mismatch",
        kind: "mismatch",
      };
    }
    return {
      kind: "verified",
      resultHash: await verifiedResultHash(plan, this.#organizationId),
    };
  }

  async #removeMembership(
    plan: Extract<ExecutablePlan, { kind: "deprovision" }>,
    beforeDispatch: () => Promise<void>,
  ): Promise<ProviderApplyReceipt> {
    if (plan.target.providerId !== "github")
      throw new GitHubUnsafeMutationError();
    await reserveIdentityWriteBudget(
      this.#identityBudget,
      plan.subject.googleUserId,
    );
    const current = await this.observe(plan.subject);
    if (current.kind === "absent")
      return receiptFor(plan, this.#organizationId);
    if (
      current.kind !== "present" ||
      current.account.providerId !== "github" ||
      current.account.githubLogin !== plan.target.githubLogin ||
      current.account.githubUserId !== plan.target.githubUserId
    ) {
      throw new GitHubIdentityMismatchError();
    }
    await this.#assertGoogleAuthority(plan);
    await beforeDispatch();
    const login = plan.target.githubLogin;
    const outcome = await providerWrite(async () => {
      const response = await this.#fetchImpl(this.#membershipUrl(login), {
        headers: this.#headers(),
        method: "DELETE",
      });
      await response.body?.cancel();
      if (response.status !== 204 && response.status !== 404) {
        throw new Error(
          `github_membership_delete_http_${String(response.status)}`,
        );
      }
    });

    let readback: ProviderObservation;
    try {
      readback = await this.observe(plan.subject);
    } catch (readbackFailure) {
      if (outcome.kind === "acknowledged")
        throw normalizeError(readbackFailure);
      throw ambiguousMutationError(outcome.error, readbackFailure);
    }
    if (readback.kind === "absent")
      return receiptFor(plan, this.#organizationId);
    if (outcome.kind === "uncertain") throw outcome.error;
    throw new GitHubReadbackMismatchError();
  }

  async #assertGoogleAuthority(
    plan: Extract<ExecutablePlan, { kind: "deprovision" }>,
  ): Promise<void> {
    if (plan.target.providerId !== "github")
      throw new GitHubUnsafeMutationError();
    // The provider and budget reads can race a Google reactivation or identity remapping.
    // Refresh the immutable Google subject at the last boundary before the write.
    const authority = await this.#readGoogleAuthority(
      plan.subject.googleUserId,
    );
    if (
      authority?.googleUserId !== plan.subject.googleUserId ||
      authority.primaryEmail !== plan.subject.primaryEmail ||
      authority.lifecycle.kind === "active" ||
      protectedIdentityBlocker(authority) !== undefined ||
      authority.github.kind !== "verified" ||
      authority.github.githubUserId !== plan.target.githubUserId ||
      authority.github.githubLogin !== plan.target.githubLogin
    ) {
      throw new Error("github_deprovision_google_authority_changed");
    }
  }

  async #assertOrganizationPin(): Promise<void> {
    const response = await this.#fetchImpl(
      `https://api.github.com/orgs/${encodeURIComponent(this.#organizationLogin)}`,
      { headers: this.#headers() },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `github_organization_observation_http_${String(response.status)}`,
      );
    }
    const organization = GitHubOrganizationSchema.parse(await response.json());
    if (
      String(organization.id) !== this.#organizationId ||
      organization.login !== this.#organizationLogin
    ) {
      throw new GitHubOrganizationPinMismatchError();
    }
  }

  async #getUser(login: z.output<typeof GitHubLoginSchema>) {
    const response = await this.#fetchImpl(
      `https://api.github.com/users/${encodeURIComponent(login)}`,
      {
        headers: this.#headers(),
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `github_user_observation_http_${String(response.status)}`,
      );
    }
    const user = GitHubUserSchema.parse(await response.json());
    return {
      githubLogin: user.login,
      githubUserId: GitHubUserIdSchema.parse(String(user.id)),
      providerId: this.providerId,
    } as const;
  }

  async #getMembership(login: z.output<typeof GitHubLoginSchema>) {
    const response = await this.#fetchImpl(this.#membershipUrl(login), {
      headers: this.#headers(),
    });
    if (response.status === 404) {
      await response.body?.cancel();
      return null;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `github_membership_observation_http_${String(response.status)}`,
      );
    }
    return GitHubMembershipSchema.parse(await response.json());
  }

  async #residualAccess(subject: AuthorityIdentity): Promise<null | string> {
    if (subject.github.kind !== "verified")
      throw new GitHubIdentityMismatchError();
    const identity = subject.github;
    const base = `https://api.github.com/orgs/${encodeURIComponent(this.#organizationLogin)}`;
    const [collaborators, invitations] = await Promise.all([
      this.#listResidualSurface(
        `${base}/outside_collaborators`,
        GitHubUserSchema,
      ),
      this.#listResidualSurface(`${base}/invitations`, GitHubInvitationSchema),
    ]);
    if (
      collaborators.some(
        ({ id, login }) =>
          String(id) === identity.githubUserId ||
          login === identity.githubLogin,
      )
    ) {
      return "GitHub outside-collaborator access remains; organization membership removal cannot revoke this access.";
    }
    const emails = new Set(
      [subject.primaryEmail, ...(subject.aliases ?? [])].map((email) =>
        email.toLowerCase(),
      ),
    );
    if (
      invitations.some(
        ({ login, email, invitee }) =>
          login === identity.githubLogin ||
          invitee?.login === identity.githubLogin ||
          String(invitee?.id) === identity.githubUserId ||
          (email != null && emails.has(email.toLowerCase())),
      )
    ) {
      return "A pending GitHub organization invitation remains; cancellation is required before offboarding is complete.";
    }
    if (
      invitations.some(
        ({ login, email, invitee }) =>
          login == null && email == null && invitee == null,
      )
    ) {
      throw new Error("github_invitation_identity_unresolved");
    }
    return null;
  }

  async #listResidualSurface<T>(
    url: string,
    schema: z.ZodType<T>,
  ): Promise<T[]> {
    const items: T[] = [];
    for (let page = 1; page <= 10; page += 1) {
      // eslint-disable-next-line no-await-in-loop -- Bounded serial pagination must prove complete inventory before absence.
      const response = await this.#fetchImpl(
        `${url}?per_page=100&page=${String(page)}`,
        {
          headers: this.#headers(),
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!response.ok) {
        // eslint-disable-next-line no-await-in-loop -- Dispose the failed page before surfacing the incomplete inventory.
        await response.body?.cancel();
        throw new Error(
          `github_residual_access_inventory_http_${String(response.status)}`,
        );
      }
      // eslint-disable-next-line no-await-in-loop -- Each page must validate before the next request.
      const batch = z.array(schema).parse(await response.json());
      items.push(...batch);
      if (
        batch.length < 100 &&
        !(response.headers.get("link") ?? "").includes('rel="next"')
      )
        return items;
    }
    throw new Error("github_residual_access_inventory_page_limit");
  }

  #headers(): HeadersInit {
    return {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${this.#token}`,
      "user-agent": "sarj-identity-provisioning",
      "x-github-api-version": "2022-11-28",
    };
  }

  #membershipUrl(login: z.output<typeof GitHubLoginSchema>): string {
    return `https://api.github.com/orgs/${encodeURIComponent(this.#organizationLogin)}/memberships/${encodeURIComponent(login)}`;
  }
}

export class GitHubOrganizationPinMismatchError extends Error {
  constructor() {
    super("github_organization_pin_mismatch");
    this.name = "GitHubOrganizationPinMismatchError";
  }
}

export class GitHubIdentityMismatchError extends Error {
  constructor() {
    super("github_identity_mismatch");
    this.name = "GitHubIdentityMismatchError";
  }
}

export class GitHubUnsafeMutationError extends Error {
  constructor() {
    super("github_deprovision_only_connector_rejected_mutation");
    this.name = "GitHubUnsafeMutationError";
  }
}

export class GitHubReadbackMismatchError extends Error {
  constructor() {
    super("github_deprovision_readback_mismatch");
    this.name = "GitHubReadbackMismatchError";
  }
}

function blocked(
  subject: AuthorityIdentity,
  detail: string,
): ProviderPlanningDecision {
  return DesiredProvisioningPlanSchema.parse({
    blockers: [{ code: "safety-policy", detail }],
    kind: "blocked",
    subject,
  });
}

function planMatchesAuthority(
  plan: Extract<ExecutablePlan, { kind: "deprovision" }>,
): boolean {
  return (
    plan.target.providerId === "github" &&
    plan.subject.github.kind === "verified" &&
    plan.subject.github.githubLogin === plan.target.githubLogin &&
    plan.subject.github.githubUserId === plan.target.githubUserId
  );
}

function providerReceiptId(
  plan: Extract<ExecutablePlan, { kind: "deprovision" }>,
  organizationId: string,
): string {
  if (plan.target.providerId !== "github")
    throw new GitHubUnsafeMutationError();
  return `github:${organizationId}:${plan.target.githubUserId}:absent`;
}

function receiptFor(
  plan: Extract<ExecutablePlan, { kind: "deprovision" }>,
  organizationId: string,
): ProviderApplyReceipt {
  return ProviderApplyReceiptSchema.parse({
    idempotencyKey: plan.idempotencyKey,
    providerReceiptId: providerReceiptId(plan, organizationId),
  });
}

async function verifiedResultHash(
  plan: Extract<ExecutablePlan, { kind: "deprovision" }>,
  organizationId: string,
): Promise<ReturnType<typeof identityProvisioningSha256>> {
  const canonical = JSON.stringify({
    githubUserId:
      plan.target.providerId === "github" ? plan.target.githubUserId : null,
    organizationId,
    organizationState: "absent",
    provider: "github",
  });
  return identityProvisioningSha256(await sha256(canonical));
}

function ambiguousMutationError(
  writeFailure: unknown,
  readbackFailure: unknown,
): Error {
  return new Error("github_deprovision_write_and_readback_failed", {
    cause: new AggregateError(
      [normalizeError(writeFailure), normalizeError(readbackFailure)],
      "github_deprovision_write_and_readback_failures",
    ),
  });
}

function normalizeError(error: unknown): Error {
  return error instanceof Error
    ? error
    : new Error("unknown_github_deprovision_failure");
}
