import { z } from "zod";

import {
  type AuthorityIdentity,
  GoogleUserIdSchema,
  provisioningIdempotencyKey,
} from "../catalog/identity-authority.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import { projectGoogleDirectoryAuthority } from "../identity-lifecycle/project-google-directory-authority.ts";
import type { AttioDeprovisionAuthority } from "../identity-provisioning/attio-deprovision-authority-capture.ts";
import {
  type AttioDeprovisionAuthoritySnapshot,
  AttioDeprovisionAuthoritySnapshotSchema,
} from "../identity-provisioning/attio-deprovision-authority-snapshot-store.ts";
import { GitHubDeprovisionGoogleAuthoritySnapshotSchema } from "../identity-provisioning/github-deprovision-google-authority-contract.ts";
import {
  googleDeprovisionIdentityEmails,
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

export const ATTIO_DEPROVISION_OPERATION_ID =
  "workspace-directory.attio-deprovision";
export const ATTIO_DEPROVISION_POLICY_VERSION = "attio-deprovision-plan/v1";
const ACTION_ID = "workspace-directory.attio-deprovision.remove";
const REQUIRED_SCOPE = "user_management:read";
const AttioUserIdSchema = z.uuid();
const LifecycleSchema = z.enum(["archived", "deleted", "suspended"]);
const AttioStateSchema = z.enum(["active-member", "pending-invite"]);
const AttioDeprovisionConfigurationSchema = z.strictObject({
  requiredScope: z.literal(REQUIRED_SCOPE),
  workspaceId: z.uuid(),
});

export const AttioDeprovisionInputSchema = z.strictObject({
  attioUserId: AttioUserIdSchema,
  googleUserId: GoogleUserIdSchema,
  schemaVersion: z.literal(ATTIO_DEPROVISION_POLICY_VERSION),
});

const AttioDeprovisionDetailsSchema = z.strictObject({
  attioState: AttioStateSchema,
  attioUserId: AttioUserIdSchema,
  authorityRevision: z.string().trim().min(1),
  googleUserId: GoogleUserIdSchema,
  idempotencyKey: z.string().trim().min(1),
  lifecycle: LifecycleSchema,
  providerPlanHash: z.string().regex(/^[a-f0-9]{64}$/u),
  schemaVersion: z.literal(ATTIO_DEPROVISION_POLICY_VERSION),
  workspaceId: z.uuid(),
});

type GoogleAuthoritySnapshot = z.output<
  typeof GitHubDeprovisionGoogleAuthoritySnapshotSchema
>;
interface CapturedAttioDeprovisionAuthority {
  readonly attio: AttioDeprovisionAuthority;
  readonly digests: AttioDeprovisionAuthoritySnapshot["digests"];
  readonly google: GoogleAuthoritySnapshot;
}

export interface AttioDeprovisionOperationPorts {
  /** Returns both complete provider inventories from one atomic, freshness-checked KV read. */
  captureAuthority(): Promise<AttioDeprovisionAuthoritySnapshot>;
  workspaceId: string;
}

/* Signed, read-only planning for one Google-authoritative Attio SCIM deprovision. */
export function createAttioDeprovisionOperation(
  ports: AttioDeprovisionOperationPorts,
): RegisteredOperation {
  const rawConfiguration = {
    requiredScope: REQUIRED_SCOPE,
    workspaceId: ports.workspaceId,
  };
  return defineOperation({
    buildPlan: (input) => buildPlan(input, ports, rawConfiguration),
    detailsSchema: AttioDeprovisionDetailsSchema.transform((details) =>
      JsonValueSchema.parse(details),
    ),
    inputSchema: AttioDeprovisionInputSchema,
    metadata: {
      destructive: true,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["attio", "configuration", "google-workspace"],
      summary:
        "Plan Google-authoritative suspension or invitation cancellation in Attio.",
      supportsApply: false,
      supportsPlan: true,
      targetSystems: ["attio"],
    },
    name: ATTIO_DEPROVISION_OPERATION_ID,
    policyVersion: ATTIO_DEPROVISION_POLICY_VERSION,
    ttlSeconds: 10 * 60,
  });
}

async function buildPlan(
  input: z.output<typeof AttioDeprovisionInputSchema>,
  ports: AttioDeprovisionOperationPorts,
  rawConfiguration: {
    readonly requiredScope: string;
    readonly workspaceId: string;
  },
) {
  const configurationFingerprint = await contentHash(rawConfiguration);
  const configuration =
    AttioDeprovisionConfigurationSchema.safeParse(rawConfiguration);
  if (!configuration.success) {
    return blockedPlan(
      [
        blocker(
          "attio_configuration_invalid",
          "The pinned Attio workspace configuration is invalid.",
        ),
      ],
      [
        fingerprint(
          "configuration",
          "attio-workspace",
          "attio-deprovision-policy",
          configurationFingerprint,
        ),
      ],
    );
  }

  const snapshot = await captureAuthority(ports);
  const googleFingerprint = snapshot.digests.google;
  const attioFingerprint = snapshot.digests.attio;
  const fingerprints = [
    fingerprint(
      "configuration",
      configuration.data.workspaceId,
      "attio-deprovision-policy",
      configurationFingerprint,
    ),
    fingerprint(
      "google-workspace",
      input.googleUserId,
      "directory-authority",
      googleFingerprint,
    ),
    fingerprint(
      "attio",
      `${configuration.data.workspaceId}:${input.attioUserId}`,
      "scim-user-inventory",
      attioFingerprint,
    ),
  ];
  const diagnostics = validateGoogleDeprovisionAuthority(snapshot.google);
  validateAttio(snapshot.attio, configuration.data.workspaceId, diagnostics);
  const googleUser = resolveGoogleDeprovisionTarget(
    snapshot.google,
    input.googleUserId,
    diagnostics,
  );
  const attioUser = resolveAttio(
    snapshot.attio,
    input.attioUserId,
    diagnostics,
  );
  if (googleUser === null || attioUser === null || hasBlocker(diagnostics)) {
    return blockedPlan(diagnostics, fingerprints);
  }
  // SCIM User and REST workspace-member IDs are separate provider contracts. Correlate the exact
  // SCIM target to its supplemental REST role authority only after its email identity is unique.
  const targetAttioEmails = attioEmails(attioUser);
  const workspaceMemberMatches = snapshot.attio.workspaceMembers.filter(
    (member) => targetAttioEmails.has(member.emailAddress),
  );
  if (workspaceMemberMatches.length > 1) {
    diagnostics.push(
      blocker(
        "attio_workspace_member_ambiguous",
        "The exact Attio SCIM identity matches multiple workspace-member authorities.",
      ),
    );
    return blockedPlan(diagnostics, fingerprints);
  }
  const workspaceMember = workspaceMemberMatches[0];
  if (!sameIdentity(googleUser, attioUser)) {
    diagnostics.push(
      blocker(
        "attio_identity_mismatch",
        "The exact Attio SCIM user does not match any authoritative email on the exact Google identity.",
      ),
    );
    return blockedPlan(diagnostics, fingerprints);
  }
  const authority = projectAuthority(googleUser, snapshot.google.capturedAt);
  if (authority.lifecycle.kind === "active") {
    diagnostics.push(
      blocker(
        "google_identity_active",
        `Google Workspace still marks immutable user ${input.googleUserId} active; deprovision is blocked.`,
      ),
    );
    return blockedPlan(diagnostics, fingerprints);
  }
  if (!attioUser.active) {
    return inactiveAttioPlan(workspaceMember, diagnostics, fingerprints);
  }
  if (
    attioUser.appRole === "admin" ||
    workspaceMember?.accessLevel === "admin"
  ) {
    diagnostics.push(
      blocker(
        "attio_admin_deprovision_blocked",
        "Attio administrators require an explicit last-admin safety policy before deprovisioning.",
      ),
    );
    return blockedPlan(diagnostics, fingerprints);
  }
  if (
    workspaceMember !== undefined &&
    attioUser.appRole !== workspaceMember.accessLevel
  ) {
    diagnostics.push(
      blocker(
        "attio_role_inconsistent",
        "The exact Attio workspace-member and SCIM role authorities disagree or omit a role.",
      ),
    );
    return blockedPlan(diagnostics, fingerprints);
  }
  const attioState =
    workspaceMember === undefined ? "pending-invite" : "active-member";
  const providerPlanHash = await contentHash({
    active: attioUser.active,
    attioState,
    attioUserId: input.attioUserId,
    googleUserId: input.googleUserId,
    lifecycle: authority.lifecycle.kind,
    workspaceId: configuration.data.workspaceId,
  });
  const idempotencyKey = provisioningIdempotencyKey({
    action: "deprovision",
    authorityDigest: await contentHash({
      authority,
      attioUserId: input.attioUserId,
    }),
    googleUserId: authority.googleUserId,
    providerId: "attio",
  });
  return {
    applicable: true,
    changes: [
      {
        actionId: ACTION_ID,
        after: null,
        before: JsonValueSchema.parse({
          active: true,
          accessLevel: workspaceMember?.accessLevel ?? null,
          appRole: attioUser.appRole ?? null,
          attioState,
          attioUserId: input.attioUserId,
          workspaceId: configuration.data.workspaceId,
        }),
        confirmationCounts: { attioScimUserDeprovisions: 1 },
        details: JsonValueSchema.parse({
          attioState,
          attioUserId: input.attioUserId,
          authorityRevision: authority.authorityRevision,
          googleUserId: input.googleUserId,
          idempotencyKey,
          lifecycle: authority.lifecycle.kind,
          providerPlanHash,
          schemaVersion: ATTIO_DEPROVISION_POLICY_VERSION,
          workspaceId: configuration.data.workspaceId,
        }),
        display:
          attioState === "active-member"
            ? `Suspend Attio workspace member ${input.attioUserId}.`
            : `Cancel Attio workspace invitation ${input.attioUserId}.`,
        kind: "remove" as const,
        reason: `Google Workspace marks immutable user ${input.googleUserId} as ${authority.lifecycle.kind}.`,
        resource: {
          id: `${configuration.data.workspaceId}:${input.attioUserId}`,
          type: "attio-scim-user",
        },
        risk: "high" as const,
      },
    ],
    diagnostics,
    sourceFingerprints: fingerprints,
  };
}

async function captureAuthority(
  ports: AttioDeprovisionOperationPorts,
): Promise<CapturedAttioDeprovisionAuthority> {
  try {
    const snapshot = AttioDeprovisionAuthoritySnapshotSchema.parse(
      await ports.captureAuthority(),
    );
    return {
      attio: snapshot.attio,
      digests: snapshot.digests,
      google: GitHubDeprovisionGoogleAuthoritySnapshotSchema.parse({
        capturedAt: snapshot.capturedAt,
        deletedUsers: snapshot.google.deletedUsers,
        users: snapshot.google.users,
      }),
    };
  } catch (error) {
    throw new OperationSourceError("attio-deprovision.authority-snapshot", {
      cause: error,
    });
  }
}

function validateAttio(
  snapshot: AttioDeprovisionAuthority,
  workspaceId: string,
  diagnostics: OperationDiagnostic[],
): void {
  validateAttioScimAvailability(snapshot, diagnostics);
  if (snapshot.token.workspaceId !== workspaceId) {
    diagnostics.push(
      blocker(
        "attio_workspace_id_mismatch",
        "The Attio authority tenant does not match policy.",
      ),
    );
  }
  findDuplicateValues(
    snapshot.scimUsers.map(({ id }) => id),
    "duplicate_attio_user_id",
    "Attio SCIM user ID",
    diagnostics,
  );
  findDuplicateValues(
    snapshot.workspaceMembers.map(({ id }) => id.workspaceMemberId),
    "duplicate_attio_workspace_member_id",
    "Attio workspace member ID",
    diagnostics,
  );
  const emailOwners = new Map<string, string>();
  const activeScimIdsByEmail = new Map<string, Set<string>>();
  const scimById = new Map<
    string,
    AttioDeprovisionAuthority["scimUsers"][number]
  >();
  for (const user of snapshot.scimUsers) {
    scimById.set(user.id, user);
    const emails = attioEmails(user);
    for (const email of emails) {
      recordOwner(
        emailOwners,
        email,
        user.id,
        "duplicate_attio_user_email",
        "Attio SCIM identity email",
        diagnostics,
      );
      if (user.active) {
        const ids = activeScimIdsByEmail.get(email) ?? new Set<string>();
        ids.add(user.id);
        activeScimIdsByEmail.set(email, ids);
      }
    }
  }
  for (const member of snapshot.workspaceMembers) {
    const memberId = member.id.workspaceMemberId;
    const scimWithSameId = scimById.get(memberId);
    const activeScimIdsWithSameEmail = activeScimIdsByEmail.get(
      member.emailAddress,
    );
    if (
      member.id.workspaceId !== workspaceId ||
      (scimWithSameId !== undefined &&
        !attioEmails(scimWithSameId).has(member.emailAddress)) ||
      (activeScimIdsWithSameEmail?.size ?? 0) > 1
    ) {
      diagnostics.push(
        blocker(
          "attio_inventory_inconsistent",
          "The complete Attio workspace-member and SCIM inventories disagree.",
        ),
      );
    }
  }
}

function validateAttioScimAvailability(
  snapshot: AttioDeprovisionAuthority,
  diagnostics: OperationDiagnostic[],
): void {
  if (snapshot.scimStatus === "payment-required") {
    diagnostics.push(
      blocker(
        "attio_scim_payment_required",
        "Attio SCIM is not enabled for this workspace; automated deprovisioning is unavailable.",
      ),
    );
  }
}

function resolveAttio(
  snapshot: AttioDeprovisionAuthority,
  attioUserId: string,
  diagnostics: OperationDiagnostic[],
) {
  if (snapshot.scimStatus === "payment-required") return null;
  const matches = snapshot.scimUsers.filter(({ id }) => id === attioUserId);
  if (matches.length === 0) {
    diagnostics.push(
      blocker(
        "attio_identity_missing",
        `Immutable Attio SCIM user ${attioUserId} is absent from the complete authority inventory.`,
      ),
    );
  }
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

function projectAuthority(
  user: GoogleDirectoryUser,
  capturedAt: string,
): AuthorityIdentity {
  try {
    return projectGoogleDirectoryAuthority(user, capturedAt);
  } catch (error) {
    throw new OperationSourceError(
      "attio-deprovision.google-authority-projection",
      {
        cause: error,
      },
    );
  }
}

function sameIdentity(
  google: GoogleDirectoryUser,
  attio: AttioDeprovisionAuthority["scimUsers"][number],
): boolean {
  const googleIdentityEmails = googleDeprovisionIdentityEmails(google);
  return !attioEmails(attio).isDisjointFrom(googleIdentityEmails);
}

function attioEmails(
  user: AttioDeprovisionAuthority["scimUsers"][number],
): Set<string> {
  return new Set(
    [user.userName, ...user.emails.map(({ value }) => value)].map((email) =>
      email.toLowerCase(),
    ),
  );
}

function recordOwner(
  owners: Map<string, string>,
  value: string,
  owner: string,
  code: string,
  label: string,
  diagnostics: OperationDiagnostic[],
): void {
  const previous = owners.get(value);
  if (previous !== undefined && previous !== owner) {
    diagnostics.push(
      blocker(code, `${label} ${value} belongs to multiple immutable users.`),
    );
  }
  owners.set(value, owner);
}

function findDuplicateValues(
  values: readonly string[],
  code: string,
  label: string,
  diagnostics: OperationDiagnostic[],
): void {
  const seen = new Set<string>();
  const reported = new Set<string>();
  for (const value of values) {
    if (seen.has(value) && !reported.has(value)) {
      diagnostics.push(
        blocker(code, `${label} ${value} occurs more than once.`),
      );
      reported.add(value);
    }
    seen.add(value);
  }
}

function blocker(code: string, message: string): OperationDiagnostic {
  return { code, message, severity: "blocker" };
}

function hasBlocker(diagnostics: readonly OperationDiagnostic[]): boolean {
  return diagnostics.some(({ severity }) => severity === "blocker");
}

function blockedPlan(
  diagnostics: OperationDiagnostic[],
  sourceFingerprints: SourceFingerprint[],
) {
  return { applicable: false, changes: [], diagnostics, sourceFingerprints };
}

function inactiveAttioPlan(
  workspaceMember:
    | AttioDeprovisionAuthority["workspaceMembers"][number]
    | undefined,
  diagnostics: OperationDiagnostic[],
  sourceFingerprints: SourceFingerprint[],
) {
  if (
    workspaceMember !== undefined &&
    workspaceMember.accessLevel !== "suspended"
  ) {
    diagnostics.push(
      blocker(
        "attio_inactive_scim_workspace_member_present",
        "The inactive Attio SCIM identity still has a correlated REST workspace member.",
      ),
    );
    return blockedPlan(diagnostics, sourceFingerprints);
  }
  return noOpPlan(
    diagnostics,
    sourceFingerprints,
    "attio_access_already_inactive",
    "The exact Attio SCIM user is already suspended.",
  );
}

function noOpPlan(
  diagnostics: OperationDiagnostic[],
  sourceFingerprints: SourceFingerprint[],
  code: string,
  message: string,
) {
  return {
    applicable: true,
    changes: [],
    diagnostics: [...diagnostics, { code, message, severity: "info" as const }],
    sourceFingerprints,
  };
}

function fingerprint(
  authority: string,
  resourceId: string,
  resourceType: string,
  version: string,
): SourceFingerprint {
  return { authority, resourceId, resourceType, version };
}
