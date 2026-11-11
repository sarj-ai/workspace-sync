import { z } from "zod";

import {
  type AuthorityIdentity,
  GitHubLoginSchema,
  GitHubUserIdSchema,
  GoogleUserIdSchema,
  provisioningIdempotencyKey,
} from "../catalog/identity-authority.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import type { GitHubDeprovisionAuthority } from "../github-access-audit/github-deprovision-authority-contract.ts";
import { projectGoogleDirectoryAuthority } from "../identity-lifecycle/project-google-directory-authority.ts";
import { GitHubDeprovisionAuthorityPort } from "../identity-provisioning/git-hub-deprovision-authority-port.ts";
import {
  type GitHubDeprovisionGoogleAuthoritySnapshotInput,
  GitHubDeprovisionGoogleAuthoritySnapshotSchema,
} from "../identity-provisioning/github-deprovision-google-authority-contract.ts";
import {
  GitHubDesiredOrganizationAccessSchema,
  GitHubObservedOrganizationAccountSchema,
  GitHubOrganizationProvisioningPlanSchema,
  planGitHubOrganizationAccess,
} from "../identity-provisioning/github-organization-connector.ts";
import {
  fingerprintGoogleDeprovisionAuthority,
  resolveGoogleDeprovisionTarget,
  validateGoogleDeprovisionAuthority,
} from "../identity-provisioning/google-deprovision-authority.ts";
import {
  defineOperation,
  OperationSourceError,
  type RegisteredOperation,
} from "../operations/registry.ts";
import {
  JsonValueSchema,
  type OperationDiagnostic,
  type SourceFingerprint,
} from "../operations/schemas.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";

export const GITHUB_DEPROVISION_OPERATION_ID =
  "workspace-directory.github-deprovision";
const ACTION_ID = "workspace-directory.github-deprovision.remove";
const POLICY_VERSION = "github-deprovision-plan/v1";
const InactiveLifecycleKindSchema = z.enum([
  "archived",
  "deleted",
  "suspended",
]);
const ConfigurationSchema = z.strictObject({
  organization: z.strictObject({
    id: z.string().regex(/^[1-9]\d*$/u),
    login: z
      .string()
      .trim()
      .min(1)
      .transform((value) => value.toLowerCase()),
  }),
});

export const GitHubDeprovisionInputSchema = z.strictObject({
  googleUserId: GoogleUserIdSchema,
  schemaVersion: z.literal(POLICY_VERSION),
});

const GitHubAccountKeyShape = {
  githubLogin: GitHubLoginSchema,
  githubUserId: GitHubUserIdSchema,
} as const;
const GitHubDeprovisionOperationSchema = z.discriminatedUnion("kind", [
  z
    .strictObject({
      ...GitHubAccountKeyShape,
      invitationId: z.number().int().positive(),
      kind: z.literal("cancel-invitation"),
    })
    .readonly(),
  z
    .strictObject({
      ...GitHubAccountKeyShape,
      kind: z.literal("remove-organization-member"),
    })
    .readonly(),
]);
type GitHubDeprovisionOperation = z.output<
  typeof GitHubDeprovisionOperationSchema
>;

const GitHubDeprovisionDetailsSchema = z.strictObject({
  authorityRevision: z.string().min(1),
  githubLogin: z.string().min(1),
  githubUserId: z.string().regex(/^[1-9]\d*$/u),
  googleUserId: GoogleUserIdSchema,
  idempotencyKey: z.string().min(1),
  lifecycle: InactiveLifecycleKindSchema,
  operation: GitHubDeprovisionOperationSchema,
  organization: z.strictObject({
    id: z.string().regex(/^[1-9]\d*$/u),
    login: z.string().min(1),
  }),
  providerPlanHash: z.string().regex(/^[a-f0-9]{64}$/u),
  schemaVersion: z.literal(POLICY_VERSION),
});

export type GitHubDeprovisionGoogleAuthoritySnapshot =
  GitHubDeprovisionGoogleAuthoritySnapshotInput;

export interface GitHubDeprovisionOperationPorts {
  captureGitHubOrganization(): Promise<GitHubDeprovisionAuthority>;
  /** Must return complete live and deleted-user inventories from one bounded authority capture. */
  captureGoogleAuthority(): Promise<GitHubDeprovisionGoogleAuthoritySnapshot>;
  organizationId: string;
  organizationLogin: string;
}

/*
 * Read-only deprovision planning. Google Workspace is the sole lifecycle authority; this
 * operation intentionally has no APPLY callback or mutating provider capability.
 */
export function createGitHubDeprovisionOperation(
  ports: GitHubDeprovisionOperationPorts,
): RegisteredOperation {
  const rawConfiguration = {
    organization: { id: ports.organizationId, login: ports.organizationLogin },
  };

  return defineOperation({
    buildPlan: (input) => buildDeprovisionPlan(input, ports, rawConfiguration),
    detailsSchema: GitHubDeprovisionDetailsSchema.transform((details) =>
      JsonValueSchema.parse(details),
    ),
    inputSchema: GitHubDeprovisionInputSchema,
    metadata: {
      destructive: true,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["configuration", "google-workspace", "github"],
      summary:
        "Plan Google-authoritative removal of one verified inactive identity from GitHub.",
      supportsApply: false,
      supportsPlan: true,
      targetSystems: ["github"],
    },
    name: GITHUB_DEPROVISION_OPERATION_ID,
    policyVersion: POLICY_VERSION,
    ttlSeconds: 10 * 60,
  });
}

async function buildDeprovisionPlan(
  input: z.output<typeof GitHubDeprovisionInputSchema>,
  ports: GitHubDeprovisionOperationPorts,
  rawConfiguration: {
    readonly organization: { readonly id: string; readonly login: string };
  },
) {
  const configurationFingerprint = await contentHash(rawConfiguration);
  const parsedConfiguration = ConfigurationSchema.safeParse(rawConfiguration);
  if (!parsedConfiguration.success) {
    return invalidConfigurationPlan(configurationFingerprint);
  }
  const configuration = parsedConfiguration.data;
  const google = await captureGoogle(ports);
  const diagnostics = validateGoogleDeprovisionAuthority(google);
  validateGitHubIdentityMappings(google, diagnostics);
  const target = resolveGoogleDeprovisionTarget(
    google,
    input.googleUserId,
    diagnostics,
  );
  const googleFingerprint = await fingerprintGoogleDeprovisionAuthority(google);
  const authorityFingerprints = authoritySourceFingerprints(
    GoogleUserIdSchema.parse(input.googleUserId),
    googleFingerprint,
    configuration.organization.id,
    configurationFingerprint,
  );
  if (
    target === null ||
    diagnostics.some(({ severity }) => severity === "blocker")
  ) {
    return blockedPlan(diagnostics, authorityFingerprints);
  }
  const authority = projectAuthority(target, google.capturedAt, diagnostics);
  if (authority === null)
    return blockedPlan(diagnostics, authorityFingerprints);
  return buildGitHubPlan({
    authority,
    authorityFingerprints,
    configuration,
    diagnostics,
    googleUserId: input.googleUserId,
    ports,
  });
}

async function buildGitHubPlan(input: {
  readonly authority: AuthorityIdentity;
  readonly authorityFingerprints: SourceFingerprint[];
  readonly configuration: z.output<typeof ConfigurationSchema>;
  readonly diagnostics: OperationDiagnostic[];
  readonly googleUserId: z.output<typeof GoogleUserIdSchema>;
  readonly ports: GitHubDeprovisionOperationPorts;
}) {
  const desired = await desiredAbsence(input.authority);
  if (desired.kind !== "absent")
    throw new Error("github_deprovision_desired_state_invalid");
  const github = await captureGitHub(input.ports);
  const githubFingerprint = await contentHash(githubFingerprintInput(github));
  const snapshotPort = createSnapshotPort(github, input.configuration);
  const { observed, plan } = await projectGitHubAccount(snapshotPort, desired);
  const fingerprints = [
    ...input.authorityFingerprints,
    sourceFingerprint(
      "github",
      input.configuration.organization.id,
      "organization-access-snapshot",
      githubFingerprint,
    ),
  ];
  if (plan.kind === "blocked") {
    return blockedPlan(
      [
        ...input.diagnostics,
        ...plan.blockers.map((blocker) => ({
          code: `github_${blocker.code.replaceAll("-", "_")}`,
          message: blocker.detail,
          severity: "blocker" as const,
        })),
      ],
      fingerprints,
    );
  }
  if (plan.operations.length === 0) {
    return noOpPlan(input.diagnostics, fingerprints);
  }
  const providerPlanHash = await contentHash(plan);
  const operations = plan.operations.map((operation) =>
    GitHubDeprovisionOperationSchema.parse(operation),
  );
  return {
    applicable: true,
    changes: operations.map((operation) =>
      operationChange({
        desired,
        googleUserId: input.googleUserId,
        observed,
        operation,
        organization: input.configuration.organization,
        providerPlanHash,
      }),
    ),
    diagnostics: input.diagnostics,
    sourceFingerprints: fingerprints,
  };
}

function invalidConfigurationPlan(configurationFingerprint: string) {
  return {
    applicable: false,
    changes: [],
    diagnostics: [
      {
        code: "github_configuration_invalid",
        message: "The pinned GitHub organization ID or login is invalid.",
        severity: "blocker" as const,
      },
    ],
    sourceFingerprints: [
      sourceFingerprint(
        "configuration",
        "github-organization",
        "github-organization-policy",
        configurationFingerprint,
      ),
    ],
  };
}

function blockedPlan(
  diagnostics: OperationDiagnostic[],
  sourceFingerprints: SourceFingerprint[],
) {
  return { applicable: false, changes: [], diagnostics, sourceFingerprints };
}

function noOpPlan(
  diagnostics: OperationDiagnostic[],
  sourceFingerprints: SourceFingerprint[],
) {
  return {
    applicable: true,
    changes: [],
    diagnostics: [
      ...diagnostics,
      {
        code: "github_access_already_absent",
        message:
          "The verified GitHub account has no organization membership or pending invitation.",
        severity: "info" as const,
      },
    ],
    sourceFingerprints,
  };
}

function authoritySourceFingerprints(
  googleUserId: z.output<typeof GoogleUserIdSchema>,
  googleFingerprint: string,
  organizationId: string,
  configurationFingerprint: string,
): SourceFingerprint[] {
  return [
    sourceFingerprint(
      "google-workspace",
      googleUserId,
      "directory-authority",
      googleFingerprint,
    ),
    sourceFingerprint(
      "configuration",
      organizationId,
      "github-organization-policy",
      configurationFingerprint,
    ),
  ];
}

function createSnapshotPort(
  github: GitHubDeprovisionAuthority,
  configuration: z.output<typeof ConfigurationSchema>,
): GitHubDeprovisionAuthorityPort {
  try {
    return new GitHubDeprovisionAuthorityPort(github, {
      organizationId: configuration.organization.id,
      organizationLogin: configuration.organization.login,
    });
  } catch (error) {
    throw new OperationSourceError(
      "github-deprovision.github-organization-snapshot",
      {
        cause: error,
      },
    );
  }
}

async function projectGitHubAccount(
  snapshotPort: GitHubDeprovisionAuthorityPort,
  desired: Extract<
    z.output<typeof GitHubDesiredOrganizationAccessSchema>,
    { kind: "absent" }
  >,
) {
  try {
    const observed = GitHubObservedOrganizationAccountSchema.parse(
      await snapshotPort.observeAccount({
        githubLogin: desired.target.githubLogin,
        githubUserId: desired.target.githubUserId,
        primaryEmail: desired.subject.primaryEmail,
      }),
    );
    const plan = planGitHubOrganizationAccess(desired, observed);
    return {
      observed,
      plan: GitHubOrganizationProvisioningPlanSchema.parse(plan),
    };
  } catch (error) {
    throw new OperationSourceError(
      "github-deprovision.github-account-projection",
      {
        cause: error,
      },
    );
  }
}

async function captureGoogle(ports: GitHubDeprovisionOperationPorts) {
  try {
    return GitHubDeprovisionGoogleAuthoritySnapshotSchema.parse(
      await ports.captureGoogleAuthority(),
    );
  } catch (error) {
    throw new OperationSourceError("github-deprovision.google-directory", {
      cause: error,
    });
  }
}

async function captureGitHub(ports: GitHubDeprovisionOperationPorts) {
  try {
    return await ports.captureGitHubOrganization();
  } catch (error) {
    throw new OperationSourceError("github-deprovision.github-organization", {
      cause: error,
    });
  }
}

function projectAuthority(
  target: GoogleDirectoryUser,
  capturedAt: string,
  diagnostics: OperationDiagnostic[],
): AuthorityIdentity | null {
  let authority: AuthorityIdentity;
  try {
    authority = projectGoogleDirectoryAuthority(target, capturedAt);
  } catch (error) {
    throw new OperationSourceError(
      "github-deprovision.google-authority-projection",
      {
        cause: error,
      },
    );
  }
  if (authority.lifecycle.kind === "active") {
    diagnostics.push({
      code: "google_identity_active",
      message: `Google Workspace still marks immutable user ${authority.googleUserId} active; deprovision is blocked.`,
      severity: "blocker",
    });
    return null;
  }
  if (authority.github.kind !== "verified") {
    diagnostics.push({
      code: "github_identity_unlinked",
      message:
        "The inactive Google identity lacks a complete immutable SarjIdentity GitHub login and user ID mapping.",
      severity: "blocker",
    });
    return null;
  }
  return authority;
}

async function desiredAbsence(authority: AuthorityIdentity) {
  if (
    authority.lifecycle.kind === "active" ||
    authority.github.kind !== "verified"
  ) {
    throw new Error("github_deprovision_requires_inactive_verified_authority");
  }
  const target = {
    githubLogin: authority.github.githubLogin,
    githubUserId: authority.github.githubUserId,
  };
  return GitHubDesiredOrganizationAccessSchema.parse({
    idempotencyKey: provisioningIdempotencyKey({
      action: "deprovision",
      authorityDigest: await contentHash({ authority, target }),
      googleUserId: authority.googleUserId,
      providerId: "github",
    }),
    kind: "absent",
    subject: authority,
    target,
  });
}

function validateGitHubIdentityMappings(
  snapshot: z.output<typeof GitHubDeprovisionGoogleAuthoritySnapshotSchema>,
  diagnostics: OperationDiagnostic[],
): void {
  const identities = [...snapshot.users, ...snapshot.deletedUsers];
  const githubLoginOwners = new Map<string, string>();
  const githubIdOwners = new Map<string, string>();
  for (const user of identities) {
    const github = user.customSchemas?.SarjIdentity;
    if (github?.githubLogin !== undefined) {
      recordOwner(
        githubLoginOwners,
        github.githubLogin.toLowerCase(),
        user.id,
        "SarjIdentity GitHub login",
        diagnostics,
      );
    }
    if (github?.githubUserId !== undefined) {
      recordOwner(
        githubIdOwners,
        github.githubUserId,
        user.id,
        "SarjIdentity GitHub user ID",
        diagnostics,
      );
    }
  }
}

function recordOwner(
  owners: Map<string, string>,
  value: string,
  googleUserId: string,
  label: string,
  diagnostics: OperationDiagnostic[],
): void {
  const owner = owners.get(value);
  if (owner !== undefined && owner !== googleUserId) {
    diagnostics.push({
      code: "github_identity_ambiguous",
      message: `${label} ${value} belongs to multiple immutable Google users.`,
      severity: "blocker",
    });
    return;
  }
  owners.set(value, googleUserId);
}

function operationChange(input: {
  readonly desired: Extract<
    z.output<typeof GitHubDesiredOrganizationAccessSchema>,
    { kind: "absent" }
  >;
  readonly googleUserId: z.output<typeof GoogleUserIdSchema>;
  readonly observed: z.output<typeof GitHubObservedOrganizationAccountSchema>;
  readonly operation: GitHubDeprovisionOperation;
  readonly organization: { readonly id: string; readonly login: string };
  readonly providerPlanHash: string;
}) {
  const invitationId =
    input.operation.kind === "cancel-invitation"
      ? input.operation.invitationId
      : null;
  const isInvitation = invitationId !== null;
  return {
    actionId: `${ACTION_ID}.${isInvitation ? `invitation-${String(invitationId)}` : "membership"}`,
    after: null,
    before: JsonValueSchema.parse(
      isInvitation
        ? (input.observed.pendingInvitations.find(
            (invitation) => invitation.invitationId === invitationId,
          ) ?? null)
        : input.observed.membership,
    ),
    confirmationCounts: isInvitation
      ? { githubInvitationCancellations: 1 }
      : { githubOrganizationMembershipRemovals: 1 },
    details: JsonValueSchema.parse({
      authorityRevision: input.desired.subject.authorityRevision,
      githubLogin: input.desired.target.githubLogin,
      githubUserId: input.desired.target.githubUserId,
      googleUserId: input.googleUserId,
      idempotencyKey: input.desired.idempotencyKey,
      lifecycle: input.desired.subject.lifecycle.kind,
      operation: input.operation,
      organization: input.organization,
      providerPlanHash: input.providerPlanHash,
      schemaVersion: POLICY_VERSION,
    }),
    display: isInvitation
      ? `Cancel GitHub organization invitation ${String(invitationId)} for ${input.desired.target.githubLogin}.`
      : `Remove ${input.desired.target.githubLogin} from GitHub organization ${input.organization.login}.`,
    kind: "remove" as const,
    reason: `Google Workspace marks immutable user ${input.googleUserId} as ${input.desired.subject.lifecycle.kind}.`,
    resource: {
      id: `${input.organization.id}:${isInvitation ? String(invitationId) : input.desired.target.githubUserId}`,
      type: isInvitation
        ? "github-organization-invitation"
        : "github-organization-membership",
    },
    risk: "high" as const,
  };
}

function githubFingerprintInput(snapshot: GitHubDeprovisionAuthority) {
  const { capturedAt: _capturedAt, ...authority } = snapshot;
  return authority;
}

function sourceFingerprint(
  authority: string,
  resourceId: string,
  resourceType: string,
  version: string,
): SourceFingerprint {
  return { authority, resourceId, resourceType, version };
}
