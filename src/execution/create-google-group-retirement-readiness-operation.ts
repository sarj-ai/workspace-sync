import { z } from "zod";

import { sameJson, sha256Hex } from "../operations/canonical.ts";
import {
  defineOperation,
  OperationSourceError,
  type RegisteredOperation,
} from "../operations/registry.ts";
import {
  type JsonValue,
  JsonValueSchema,
  type OperationDiagnostic,
} from "../operations/schemas.ts";
import type { GoogleGroupSnapshot } from "../org-sync/channel-model.ts";
import type { IGoogleGroupsClient } from "../org-sync/google-groups-client.ts";
import type {
  GoogleGroupSettingsReader,
  GoogleGroupSettingsSnapshot,
} from "../org-sync/google-groups-settings-client.ts";

const EmailSchema = z.email().transform((value) => value.toLowerCase());
const GoogleGroupRoleSchema = z.enum(["MANAGER", "MEMBER", "OWNER"]);

export const GoogleGroupRetirementReadinessInputSchema = z.strictObject({
  googleGroupEmail: EmailSchema,
  googleGroupId: z.string().trim().min(1),
});
export type GoogleGroupRetirementReadinessInput = z.output<
  typeof GoogleGroupRetirementReadinessInputSchema
>;

const InboundMembershipSchema = z.strictObject({
  parentGroupEmail: EmailSchema,
  parentGroupId: z.string().min(1),
  role: GoogleGroupRoleSchema,
});

const RepositoryReferenceSchema = z.strictObject({
  locations: z.array(z.string().min(1)).min(1),
  repository: z.string().min(1),
  revision: z.string().min(1),
});

const AttestedRepositorySchema = z.strictObject({
  deploymentAuthorityId: z.string().min(1),
  deploymentEnvironment: z.string().min(1),
  deploymentObservedAt: z.iso.datetime({ offset: true }),
  deploymentResourceId: z.string().min(1),
  repository: z.string().min(1),
  revision: z.string().min(1),
});

const DetailsSchema = z.strictObject({
  attestedRepositories: z.array(AttestedRepositorySchema),
  dependencyEnvelopeDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  googleGroupEmail: EmailSchema,
  googleGroupId: z.string().min(1),
  inboundMemberships: z.array(InboundMembershipSchema),
  memberCount: z.number().int().nonnegative(),
  repositoryReferences: z.array(RepositoryReferenceSchema),
  settings: JsonValueSchema,
  settingsEtag: z.string().min(1),
});

export interface RepositoryDependencyAttestation {
  readonly deployedRevision: {
    readonly authorityId: string;
    readonly environment: string;
    readonly observedAt: string;
    readonly resourceId: string;
    readonly revision: string;
  };
  readonly googleGroupReferences: readonly {
    readonly googleGroupEmail: string;
    readonly googleGroupId: string;
    readonly locations: readonly string[];
  }[];
  readonly repository: string;
  readonly revision: string;
}

export interface VerifiedRepositoryDependencyEnvelope {
  readonly generatedAt: string;
  readonly registryId: string;
  readonly registryVersion: string;
  readonly repositories: readonly RepositoryDependencyAttestation[];
  /** Verification metadata is issued only after signature verification over the canonical envelope. */
  readonly verification: {
    readonly authorityId: string;
    readonly canonicalDigest: string;
    readonly keyId: string;
  };
}

export interface ExpectedRepositoryDependencyRegistry {
  readonly deploymentAuthorityId: string;
  readonly registryAuthorityId: string;
  readonly registryId: string;
  readonly registryVersion: string;
  readonly repositories: readonly string[];
}

export interface DeployedRepositoryRevision {
  readonly authorityId: string;
  readonly environment: string;
  readonly observedAt: string;
  readonly repository: string;
  readonly resourceId: string;
  readonly revision: string;
}

export interface DeploymentRevisionAuthority {
  readDeployedRevisions(
    expected: ExpectedRepositoryDependencyRegistry,
    runId: string,
  ): Promise<readonly DeployedRepositoryRevision[]>;
}

export interface GoogleGroupDependencyAuthority {
  readVerifiedDependencyEnvelope(
    expected: ExpectedRepositoryDependencyRegistry,
    target: GoogleGroupRetirementReadinessInput,
    runId: string,
  ): Promise<VerifiedRepositoryDependencyEnvelope>;
}

export interface GoogleGroupRetirementReadinessDependencies {
  dependencies: GoogleGroupDependencyAuthority;
  deployments: DeploymentRevisionAuthority;
  expectedRepositoryRegistry: ExpectedRepositoryDependencyRegistry;
  groups: Pick<IGoogleGroupsClient, "listAllGroups" | "listGroups">;
  settings: GoogleGroupSettingsReader;
}

interface ReadinessState {
  attestedRepositories: z.output<typeof AttestedRepositorySchema>[];
  dependencyEnvelopeDigest: string;
  diagnostics: OperationDiagnostic[];
  inboundMemberships: z.output<typeof InboundMembershipSchema>[];
  memberCount: number;
  repositoryReferences: z.output<typeof RepositoryReferenceSchema>[];
  settings: JsonValue;
  settingsEtag: string;
  sourceFingerprints: {
    authority: string;
    resourceId: string;
    resourceType: string;
    version: string;
  }[];
}

const ACTION_ID = "google-group-retirement-readiness:delete-candidate";
const MAX_ATTESTATION_AGE_MS = 24 * 60 * 60 * 1000;

const ExpectedRepositoryDependencyRegistrySchema = z.strictObject({
  deploymentAuthorityId: z.string().min(1),
  registryAuthorityId: z.string().min(1),
  registryId: z.string().min(1),
  registryVersion: z.string().min(1),
  repositories: z
    .array(z.string().min(1))
    .min(1)
    .refine(
      (values) => new Set(values).size === values.length,
      "repositories must be unique",
    ),
});

export function createGoogleGroupRetirementReadinessOperation(
  dependencies: GoogleGroupRetirementReadinessDependencies,
): RegisteredOperation {
  const expectedRegistry = ExpectedRepositoryDependencyRegistrySchema.parse(
    dependencies.expectedRepositoryRegistry,
  );
  return defineOperation({
    name: "workspace-directory.google-group-retirement-readiness",
    policyVersion: "2026-09-10.1",
    inputSchema: GoogleGroupRetirementReadinessInputSchema,
    detailsSchema: DetailsSchema,
    actionIds: [ACTION_ID],
    ttlSeconds: 300,
    metadata: {
      destructive: false,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:read",
      risk: "high",
      sourceSystems: [
        "google.directory",
        "google.groups-settings",
        "repository-attestations",
      ],
      summary:
        "Produce signed, read-only deletion-readiness evidence for one exact Google Group.",
      supportsApply: false,
      supportsPlan: true,
      targetSystems: ["google.groups"],
    },
    async buildPlan(input, context) {
      const state = await loadReadinessState(
        dependencies,
        expectedRegistry,
        input,
        context.now,
      );
      const ready = state.diagnostics.length === 0;
      return {
        applicable: ready,
        changes: ready
          ? [
              {
                actionId: ACTION_ID,
                after: { group: "absent" },
                before: {
                  group: "present",
                  memberCount: state.memberCount,
                  settings: state.settings,
                  settingsEtag: state.settingsEtag,
                },
                details: {
                  attestedRepositories: state.attestedRepositories,
                  dependencyEnvelopeDigest: state.dependencyEnvelopeDigest,
                  googleGroupEmail: input.googleGroupEmail,
                  googleGroupId: input.googleGroupId,
                  inboundMemberships: state.inboundMemberships,
                  memberCount: state.memberCount,
                  repositoryReferences: state.repositoryReferences,
                  settings: state.settings,
                  settingsEtag: state.settingsEtag,
                },
                display: `Deletion candidate ${input.googleGroupEmail} (read-only readiness evidence)`,
                kind: "remove",
                reason:
                  "The complete Google nesting inventory and signed repository dependency registry contain no inbound references.",
                resource: {
                  id: input.googleGroupId,
                  type: "google-group-deletion-candidate",
                },
                risk: "high",
              },
            ]
          : [],
        diagnostics: state.diagnostics,
        sourceFingerprints: state.sourceFingerprints,
      };
    },
  });
}

async function loadReadinessState(
  sources: GoogleGroupRetirementReadinessDependencies,
  expectedRegistry: ExpectedRepositoryDependencyRegistry,
  input: GoogleGroupRetirementReadinessInput,
  now: Date,
): Promise<ReadinessState> {
  try {
    const runId = crypto.randomUUID();
    const identities = await sources.groups.listAllGroups(runId);
    const targetIdentity = identities.filter(
      ({ id }) => id === input.googleGroupId,
    );
    if (
      targetIdentity.length !== 1 ||
      normalizeEmail(targetIdentity[0]?.email ?? "") !== input.googleGroupEmail
    ) {
      throw new Error("google_group_retirement_target_identity_drift");
    }
    const snapshots = await sources.groups.listGroups(
      identities.map(({ email }) => email),
      runId,
      undefined,
      false,
      true,
    );
    assertCompleteInventory(identities, snapshots);
    const target = snapshots.find(({ id }) => id === input.googleGroupId);
    if (target === undefined)
      throw new Error("google_group_retirement_target_snapshot_missing");

    const [settings, dependencyEnvelope, deployedRevisions] = await Promise.all(
      [
        sources.settings.readSettings(input, runId),
        sources.dependencies.readVerifiedDependencyEnvelope(
          expectedRegistry,
          input,
          runId,
        ),
        sources.deployments.readDeployedRevisions(expectedRegistry, runId),
      ],
    );
    assertSettingsIdentity(settings, input);
    const deploymentAuthority = validateDeploymentAuthority(
      deployedRevisions,
      expectedRegistry,
      now,
    );
    const dependencyEnvelopeDigest = await validateDependencyAuthority(
      dependencyEnvelope,
      deploymentAuthority,
      expectedRegistry,
      input,
      now,
    );
    const deployedRevisionsDigest = await sha256Hex(
      JsonValueSchema.parse(
        deploymentAuthority
          .values()
          .toArray()
          .toSorted((left, right) =>
            left.repository.localeCompare(right.repository),
          ),
      ),
    );
    const repositoryReferences = repositoryReferencesForTarget(
      dependencyEnvelope,
      input,
    );
    const inboundMemberships = findInboundMemberships(snapshots, input);
    const diagnostics: OperationDiagnostic[] = [];
    if (target.members.length > 0) {
      diagnostics.push({
        code: "google_group_is_not_empty",
        message: `${input.googleGroupEmail} still has ${String(target.members.length)} direct member(s).`,
        severity: "blocker",
      });
    }
    if (inboundMemberships.length > 0) {
      diagnostics.push({
        code: "google_group_has_inbound_nested_memberships",
        message: `${input.googleGroupEmail} is nested in ${String(inboundMemberships.length)} Google Group(s).`,
        severity: "blocker",
      });
    }
    if (repositoryReferences.length > 0) {
      diagnostics.push({
        code: "google_group_has_repository_dependencies",
        message: `${input.googleGroupEmail} is referenced by ${String(repositoryReferences.length)} deployed repository attestation(s).`,
        severity: "blocker",
      });
    }
    const inventoryDigest = await sha256Hex(
      JsonValueSchema.parse(
        snapshots
          .map((group) => ({
            email: normalizeEmail(group.email),
            id: group.id,
            members: group.members
              .map((member) => ({
                email: normalizeEmail(member.email),
                id: member.id,
                role: member.role,
                status: member.status,
                type: member.type,
              }))
              .toSorted((left, right) => left.id.localeCompare(right.id)),
          }))
          .toSorted((left, right) => left.id.localeCompare(right.id)),
      ),
    );
    const settingsDigest = await sha256Hex(
      JsonValueSchema.parse(settings.settings),
    );
    return {
      attestedRepositories: dependencyEnvelope.repositories
        .map((attestation) => ({
          deploymentAuthorityId: attestation.deployedRevision.authorityId,
          deploymentEnvironment: attestation.deployedRevision.environment,
          deploymentObservedAt: attestation.deployedRevision.observedAt,
          deploymentResourceId: attestation.deployedRevision.resourceId,
          repository: attestation.repository,
          revision: attestation.revision,
        }))
        .toSorted((left, right) =>
          left.repository.localeCompare(right.repository),
        ),
      dependencyEnvelopeDigest,
      diagnostics,
      inboundMemberships,
      memberCount: target.members.length,
      repositoryReferences,
      settings: settings.settings,
      settingsEtag: settings.etag,
      sourceFingerprints: [
        {
          authority: "google.directory",
          resourceId: "customer:my_customer:groups-and-direct-members",
          resourceType: "google-group-inventory",
          version: inventoryDigest,
        },
        {
          authority: "google.groups-settings",
          resourceId: input.googleGroupEmail,
          resourceType: "google-group-settings",
          version: `${settings.etag}:${settingsDigest}`,
        },
        {
          authority: expectedRegistry.registryAuthorityId,
          resourceId: `${expectedRegistry.registryId}:${expectedRegistry.registryVersion}`,
          resourceType: "cross-repository-dependencies",
          version: dependencyEnvelopeDigest,
        },
        {
          authority: expectedRegistry.deploymentAuthorityId,
          resourceId: "production:declared-repositories",
          resourceType: "deployed-repository-revisions",
          version: deployedRevisionsDigest,
        },
      ],
    };
  } catch (cause) {
    if (cause instanceof OperationSourceError) throw cause;
    throw new OperationSourceError("google-group-retirement-readiness", {
      cause,
    });
  }
}

function assertCompleteInventory(
  identities: readonly { email: string; id: string }[],
  snapshots: readonly GoogleGroupSnapshot[],
): void {
  const expected = new Set(identities.map(({ id }) => id));
  const actual = new Set(snapshots.map(({ id }) => id));
  if (expected.size !== identities.length || actual.size !== snapshots.length) {
    throw new Error("google_group_retirement_inventory_contains_duplicate_ids");
  }
  if (expected.size !== actual.size || !expected.isSubsetOf(actual)) {
    throw new Error("google_group_retirement_inventory_incomplete");
  }
}

function assertSettingsIdentity(
  settings: GoogleGroupSettingsSnapshot,
  input: GoogleGroupRetirementReadinessInput,
): void {
  if (
    normalizeEmail(settings.googleGroupEmail) !== input.googleGroupEmail ||
    settings.etag.trim().length === 0
  ) {
    throw new Error("google_group_retirement_settings_identity_drift");
  }
  JsonValueSchema.parse(settings.settings);
}

async function validateDependencyAuthority(
  envelope: VerifiedRepositoryDependencyEnvelope,
  deployedRevisions: ReadonlyMap<string, DeployedRepositoryRevision>,
  expected: ExpectedRepositoryDependencyRegistry,
  input: GoogleGroupRetirementReadinessInput,
  now: Date,
): Promise<string> {
  if (
    envelope.registryId !== expected.registryId ||
    envelope.registryVersion !== expected.registryVersion ||
    envelope.verification.authorityId !== expected.registryAuthorityId ||
    envelope.verification.keyId.trim().length === 0
  ) {
    throw new Error(
      "google_group_retirement_dependency_registry_identity_drift",
    );
  }
  assertFreshTimestamp(envelope.generatedAt, now, "dependency_envelope");
  const declared = new Set(expected.repositories);
  const attested = new Set(
    envelope.repositories.map(({ repository }) => repository),
  );
  if (
    attested.size !== envelope.repositories.length ||
    declared.size !== attested.size ||
    !declared.isSubsetOf(attested)
  ) {
    throw new Error("google_group_retirement_dependency_coverage_incomplete");
  }
  for (const attestation of envelope.repositories) {
    assertDependencyAttestation(attestation, deployedRevisions, input);
  }
  const canonicalDigest = await sha256Hex(dependencyEnvelopePayload(envelope));
  if (canonicalDigest !== envelope.verification.canonicalDigest) {
    throw new Error(
      "google_group_retirement_dependency_envelope_digest_mismatch",
    );
  }
  return canonicalDigest;
}

function assertDependencyAttestation(
  attestation: RepositoryDependencyAttestation,
  deployedRevisions: ReadonlyMap<string, DeployedRepositoryRevision>,
  input: GoogleGroupRetirementReadinessInput,
): void {
  const deployed = deployedRevisions.get(attestation.repository);
  if (attestation.revision !== deployed?.revision) {
    throw new Error("google_group_retirement_deployed_revision_unverified");
  }
  const attestedDeployment = JsonValueSchema.parse(
    attestation.deployedRevision,
  );
  const authoritativeDeployment = JsonValueSchema.parse({
    authorityId: deployed.authorityId,
    environment: deployed.environment,
    observedAt: deployed.observedAt,
    resourceId: deployed.resourceId,
    revision: deployed.revision,
  });
  if (!sameJson(attestedDeployment, authoritativeDeployment)) {
    throw new Error("google_group_retirement_deployed_revision_unverified");
  }
  for (const reference of attestation.googleGroupReferences) {
    const idMatch = reference.googleGroupId === input.googleGroupId;
    const emailMatch =
      normalizeEmail(reference.googleGroupEmail) === input.googleGroupEmail;
    if (idMatch !== emailMatch) {
      throw new Error("google_group_retirement_repository_identity_ambiguous");
    }
    if (idMatch && reference.locations.length === 0) {
      throw new Error(
        "google_group_retirement_repository_reference_locations_missing",
      );
    }
  }
}

function validateDeploymentAuthority(
  revisions: readonly DeployedRepositoryRevision[],
  expected: ExpectedRepositoryDependencyRegistry,
  now: Date,
): ReadonlyMap<string, DeployedRepositoryRevision> {
  const byRepository = new Map<string, DeployedRepositoryRevision>();
  for (const revision of revisions) {
    if (
      revision.authorityId !== expected.deploymentAuthorityId ||
      revision.environment !== "production" ||
      revision.resourceId.trim().length === 0 ||
      byRepository.has(revision.repository)
    ) {
      throw new Error("google_group_retirement_deployment_authority_invalid");
    }
    assertFreshTimestamp(revision.observedAt, now, "deployed_revision");
    byRepository.set(revision.repository, revision);
  }
  if (
    byRepository.size !== expected.repositories.length ||
    expected.repositories.some((repository) => !byRepository.has(repository))
  ) {
    throw new Error("google_group_retirement_deployment_coverage_incomplete");
  }
  return byRepository;
}

function repositoryReferencesForTarget(
  envelope: VerifiedRepositoryDependencyEnvelope,
  input: GoogleGroupRetirementReadinessInput,
): z.output<typeof RepositoryReferenceSchema>[] {
  return envelope.repositories.flatMap((attestation) => {
    const locations = attestation.googleGroupReferences
      .filter(
        (reference) =>
          reference.googleGroupId === input.googleGroupId &&
          normalizeEmail(reference.googleGroupEmail) === input.googleGroupEmail,
      )
      .flatMap(({ locations: values }) => values)
      .toSorted((left, right) => left.localeCompare(right));
    return locations.length === 0
      ? []
      : {
          locations,
          repository: attestation.repository,
          revision: attestation.revision,
        };
  });
}

function dependencyEnvelopePayload(
  envelope: VerifiedRepositoryDependencyEnvelope,
): JsonValue {
  return JsonValueSchema.parse({
    generatedAt: envelope.generatedAt,
    registryId: envelope.registryId,
    registryVersion: envelope.registryVersion,
    repositories: envelope.repositories,
  });
}

function assertFreshTimestamp(
  value: string,
  now: Date,
  component: string,
): void {
  const timestamp = Date.parse(value);
  if (
    !Number.isFinite(timestamp) ||
    timestamp > now.getTime() ||
    now.getTime() - timestamp > MAX_ATTESTATION_AGE_MS
  ) {
    throw new Error(`google_group_retirement_${component}_invalid_or_stale`);
  }
}

function findInboundMemberships(
  snapshots: readonly GoogleGroupSnapshot[],
  target: GoogleGroupRetirementReadinessInput,
): z.output<typeof InboundMembershipSchema>[] {
  const inbound: z.output<typeof InboundMembershipSchema>[] = [];
  for (const parent of snapshots) {
    for (const member of parent.members) {
      if (member.type !== "GROUP") continue;
      const idMatch = member.id === target.googleGroupId;
      const emailMatch =
        normalizeEmail(member.email) === target.googleGroupEmail;
      if (idMatch !== emailMatch) {
        throw new Error("google_group_retirement_nested_identity_ambiguous");
      }
      if (idMatch) {
        inbound.push({
          parentGroupEmail: normalizeEmail(parent.email),
          parentGroupId: parent.id,
          role: member.role,
        });
      }
    }
  }
  return inbound.toSorted((left, right) =>
    left.parentGroupEmail.localeCompare(right.parentGroupEmail),
  );
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}
