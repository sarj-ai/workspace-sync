import { z } from "zod";

import {
  assertDistinctGitHubOrganizationCredentials,
  githubProviderObservationStage,
} from "../identity-provisioning/github-organization-api-port.ts";
import { GitHubProvisioningBlockerCodeSchema } from "../identity-provisioning/github-organization-connector.ts";
import { logErrorEvent } from "../shared/log-event.ts";
import type { CapturedManagedGitHubAccess } from "./github-access-managed.ts";

const DiagnosticCodeSchema = z.enum([
  "credential_missing",
  "credential_not_separated",
  "source_unavailable",
  "source_employee_authority_unavailable",
  "source_google_authority_unavailable",
  "source_github_inventory_unavailable",
  "source_authority_projection_unavailable",
  "source_snapshot_port_unavailable",
  "source_account_planning_unavailable",
  "source_team_fingerprint_unavailable",
  "source_authority_fingerprint_unavailable",
  "source_blocked",
  "target_unavailable",
  "provider_evidence_unavailable",
  "provider_http_401",
  "provider_http_403",
  "provider_http_404",
  "provider_http_429",
  "provider_request_headers_invalid",
  "provider_request_transport_failed",
  "provider_transport_illegal_invocation",
  "provider_transport_network_failure",
  "provider_transport_request_context_inactive",
  "provider_transport_type_error",
  "provider_writer_response_invalid",
  "provider_target_ineligible",
  "write_permission_unproven",
]);
const PermissionEvidenceSchema = z.enum([
  "unavailable",
  "read-verified-write-unproven",
]);
const KNOWN_PROVIDER_ERROR_CODES = [
  "github_identity_pin_mismatch",
  "github_organization_pages_bound_exceeded",
  "github_organization_pin_mismatch",
  "github_organization_requests_bound_exceeded",
  "github_request_headers_invalid",
  "github_request_transport_failed",
  "github_saml_identity_graphql_error",
  "github_saml_identity_invalid_cursor",
  "github_team_outside_managed_scope",
  "github_unresolved_privileged_invitation",
  "github_writer_tenant_response_invalid",
] as const;
const PROVIDER_DIAGNOSTICS = [
  ["github_request_headers_invalid", "provider_request_headers_invalid"],
  [
    "github_request_transport_illegal_invocation",
    "provider_transport_illegal_invocation",
  ],
  [
    "github_request_transport_network_failure",
    "provider_transport_network_failure",
  ],
  [
    "github_request_transport_request_context_inactive",
    "provider_transport_request_context_inactive",
  ],
  ["github_request_transport_type_error", "provider_transport_type_error"],
  ["github_request_transport_failed", "provider_request_transport_failed"],
  ["github_writer_tenant_response_invalid", "provider_writer_response_invalid"],
  ["provider_http_401", "provider_http_401"],
  ["provider_http_403", "provider_http_403"],
  ["provider_http_404", "provider_http_404"],
  ["provider_http_429", "provider_http_429"],
] as const;
export const GithubWriterReadinessSchema = z.strictObject({
  mutationDisabled: z.boolean(),
  writesAttempted: z.literal(0),
  credentialsSeparated: z.boolean(),
  sourceComplete: z.boolean(),
  globalBlockerCount: z.number().int().nonnegative(),
  tenantPinVerified: z.boolean(),
  observedIdentityVerified: z.boolean(),
  permissionEvidence: PermissionEvidenceSchema,
  providerBlockerCounts: z.partialRecord(
    GitHubProvisioningBlockerCodeSchema,
    z.number().int().nonnegative(),
  ),
  diagnostics: z.array(DiagnosticCodeSchema),
});
export type GithubWriterReadiness = z.output<
  typeof GithubWriterReadinessSchema
>;

export interface GithubWriterReadinessDependencies {
  capture(): Promise<CapturedManagedGitHubAccess>;
  verifyWriterTenant(): Promise<void>;
}

/* Observes one naturally eligible identity; never infers write authorization from successful GETs. */
export async function inspectGithubWriterReadiness(
  config: {
    auditToken: string;
    writerToken: string;
    mutationDisabled: boolean;
  },
  dependencies: GithubWriterReadinessDependencies,
): Promise<GithubWriterReadiness> {
  const report: GithubWriterReadiness = {
    mutationDisabled: config.mutationDisabled,
    writesAttempted: 0,
    credentialsSeparated: false,
    sourceComplete: false,
    globalBlockerCount: 0,
    tenantPinVerified: false,
    observedIdentityVerified: false,
    permissionEvidence: "unavailable",
    providerBlockerCounts: {},
    diagnostics: ["write_permission_unproven"],
  };
  if (config.auditToken.trim() === "" || config.writerToken.trim() === "") {
    report.diagnostics.push("credential_missing");
    return report;
  }
  try {
    await assertDistinctGitHubOrganizationCredentials(
      config.auditToken,
      config.writerToken,
    );
  } catch {
    report.diagnostics.push("credential_not_separated");
    return report;
  }
  report.credentialsSeparated = true;
  try {
    await dependencies.verifyWriterTenant();
    report.tenantPinVerified = true;
  } catch (error) {
    const detail = githubProviderErrorDetail(error);
    logErrorEvent("github_writer_readiness.provider_unavailable", {
      "error_code": githubProviderErrorCode(error, detail),
    });
    report.diagnostics.push(providerDiagnostic(detail));
    return report;
  }
  const captured = await dependencies.capture().catch((error: unknown) => {
    logErrorEvent("github_writer_readiness.source_unavailable", {
      "error_code": "source_unavailable",
    });
    return { error: sourceDiagnostic(error) } as const;
  });
  if ("error" in captured) {
    report.diagnostics.push(captured.error);
    return report;
  }
  report.globalBlockerCount = captured.branch.diagnostics.filter(
    ({ severity }) => severity === "blocker",
  ).length;
  for (const account of captured.branch.accountPlans) {
    if (account.plan.kind !== "blocked") continue;
    for (const { code } of account.plan.blockers) {
      report.providerBlockerCounts[code] =
        (report.providerBlockerCounts[code] ?? 0) + 1;
    }
  }
  report.sourceComplete = report.globalBlockerCount === 0;
  if (!report.sourceComplete) report.diagnostics.push("source_blocked");
  const candidate = captured.branch.accountPlans.find(
    ({ plan }) => plan.kind === "executable" && plan.desired.kind === "present",
  );
  if (candidate?.plan.desired.kind !== "present") {
    report.diagnostics.push("target_unavailable");
    return report;
  }
  const identity = candidate.plan.desired.subject.github;
  const observed = captured.observedByUserId.get(candidate.googleUserId);
  if (
    observed?.identity.githubUserId !== identity.githubUserId ||
    observed.identity.githubLogin !== identity.githubLogin ||
    observed.membership?.role !== "member" ||
    !observed.samlLinked ||
    !observed.repositoryInventoryComplete ||
    observed.outsideCollaborator ||
    observed.pendingInvitations.length > 0
  ) {
    report.diagnostics.push("provider_target_ineligible");
    return report;
  }
  report.observedIdentityVerified = true;
  report.permissionEvidence = "read-verified-write-unproven";
  return GithubWriterReadinessSchema.parse(report);
}

function githubProviderErrorCode(
  error: unknown,
  detail = githubProviderErrorDetail(error),
): string {
  const observationStage = githubProviderObservationStage(error);
  return observationStage === undefined
    ? detail
    : `github_provider_stage_${observationStage}:${detail}`;
}

function providerDiagnostic(
  errorDetail: string,
): z.output<typeof DiagnosticCodeSchema> {
  return (
    PROVIDER_DIAGNOSTICS.find(
      ([providerError]) => providerError === errorDetail,
    )?.[1] ?? "provider_evidence_unavailable"
  );
}

function githubProviderErrorDetail(error: unknown): string {
  if (error instanceof z.ZodError) return "schema_validation";
  if (!(error instanceof Error)) return "unknown";
  if (error.name === "TimeoutError" || error.name === "AbortError")
    return "request_timeout";
  const httpStatus = /_http_(\d{3})$/u.exec(error.message)?.[1];
  if (httpStatus !== undefined) return `provider_http_${httpStatus}`;
  if (error.message === "github_request_transport_failed") {
    return githubTransportFailureDetail(error.cause);
  }
  const knownProviderCodes: readonly string[] = KNOWN_PROVIDER_ERROR_CODES;
  return knownProviderCodes.includes(error.message) ? error.message : "unknown";
}

function githubTransportFailureDetail(cause: unknown): string {
  if (!(cause instanceof Error)) return "github_request_transport_failed";
  const message = cause.message.toLowerCase();
  if (message.includes("illegal invocation")) {
    return "github_request_transport_illegal_invocation";
  }
  if (
    message.includes("request context") ||
    message.includes("cannot perform i/o") ||
    message.includes("different request")
  ) {
    return "github_request_transport_request_context_inactive";
  }
  if (
    message.includes("network connection lost") ||
    message.includes("fetch failed") ||
    message.includes("network error")
  ) {
    return "github_request_transport_network_failure";
  }
  return cause instanceof TypeError
    ? "github_request_transport_type_error"
    : "github_request_transport_failed";
}

function sourceDiagnostic(
  error: unknown,
): z.output<typeof DiagnosticCodeSchema> {
  const parsed = DiagnosticCodeSchema.safeParse(
    error instanceof Error ? error.message : "",
  );
  return parsed.success && parsed.data.startsWith("source_")
    ? parsed.data
    : "source_unavailable";
}
