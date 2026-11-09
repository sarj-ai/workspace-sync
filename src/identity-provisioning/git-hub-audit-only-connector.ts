import type {
  AuthorityIdentity,
  DesiredProvisioningPlan,
} from "../catalog/identity-authority.ts";
import type {
  AuditOnlyIdentityProviderConnector,
  IdentityProviderObserver,
  IdentityProviderPlanner,
  IdentityProviderPlanningContext,
  ProviderApplyReceipt,
  ProviderObservation,
  ProviderPlanningDecision,
  ProviderVerification,
} from "./contracts.ts";
import { providerLifecycleProtocol } from "./contracts.ts";

export class GitHubAuditOnlyConnector implements AuditOnlyIdentityProviderConnector {
  readonly protocol = providerLifecycleProtocol({
    authority: "google-workspace",
    execution: "audit-only",
    managedActions: [],
    providerId: "github",
    verification: "authoritative-readback",
  });
  readonly execution = "audit-only";
  readonly providerId = "github";
  readonly #observer: IdentityProviderObserver;
  readonly #planner: IdentityProviderPlanner;

  constructor(
    observer: IdentityProviderObserver,
    planner: IdentityProviderPlanner,
  ) {
    this.#observer = observer;
    this.#planner = planner;
  }

  async observe(subject: AuthorityIdentity): Promise<ProviderObservation> {
    const observation = await this.#observer.observe(subject);
    if (observation.providerId !== this.providerId) {
      throw new Error("github_observer_returned_wrong_provider");
    }
    return observation;
  }

  plan(
    subject: AuthorityIdentity,
    observation: ProviderObservation,
    context?: IdentityProviderPlanningContext,
  ): Promise<ProviderPlanningDecision> {
    return this.#planner.plan(subject, observation, context);
  }

  verify(
    plan: Exclude<DesiredProvisioningPlan, { kind: "blocked" }>,
    receipt: ProviderApplyReceipt,
  ): Promise<ProviderVerification> {
    if (
      plan.target.providerId !== this.providerId ||
      receipt.idempotencyKey !== plan.idempotencyKey
    ) {
      return Promise.resolve({
        errorCode: "github_audit_receipt_mismatch",
        kind: "mismatch",
      });
    }
    return Promise.resolve({
      errorCode: "github_audit_only",
      kind: "mismatch",
    });
  }
}
