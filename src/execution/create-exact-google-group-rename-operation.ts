import {
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import { sameJson, sha256Hex } from "../operations/canonical.ts";
import {
  defineOperation,
  OperationSourceError,
  type RegisteredOperation,
} from "../operations/registry.ts";
import type { JsonValue } from "../operations/schemas.ts";
import {
  type GoogleGroupRenameDetails,
  GoogleGroupRenameDetailsSchema,
  type GoogleGroupRenameInput,
  GoogleGroupRenameInputSchema,
  type GoogleGroupRenameSnapshot,
  GoogleGroupRenameSourceError,
  type IGoogleGroupRenameClient,
  isExactRenameReadback,
} from "../org-sync/google-group-rename-client.ts";
import { GOOGLE_GROUP_MUTATION_RESOURCE_LEASE_KEY } from "./google-group-mutation-resource-lease-key.ts";

const ACTION_ID = "exact-google-group-rename:rename";
const APPLY_LEASE_MS = 5 * 60 * 1000;
const APPLY_MIN_HEADROOM_MS = 30 * 1000;

export interface ExactGoogleGroupRenameDependencies {
  client: IGoogleGroupRenameClient;
  leaseRepository: ResourceLeaseRepository;
  protectedGoogleGroupEmails: readonly string[];
  protectedGoogleGroupIds: readonly string[];
}

interface ExactRenameState {
  managed: JsonValue;
  phase: "converged" | "pending";
  snapshot: GoogleGroupRenameSnapshot;
}

export function createExactGoogleGroupRenameOperation(
  dependencies: ExactGoogleGroupRenameDependencies,
): RegisteredOperation {
  const protectedEmails = new Set(
    dependencies.protectedGoogleGroupEmails.map((email) => email.toLowerCase()),
  );
  const protectedIds = new Set(dependencies.protectedGoogleGroupIds);
  return defineOperation({
    name: "workspace-directory.exact-google-group-rename",
    policyVersion: "2026-09-10.3",
    inputSchema: GoogleGroupRenameInputSchema,
    detailsSchema: GoogleGroupRenameDetailsSchema,
    actionIds: [ACTION_ID],
    ttlSeconds: 300,
    metadata: {
      destructive: true,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["google.directory", "google.groups-settings"],
      summary:
        "Rename one exact Google group in place after a signed collision-safe review.",
      supportsApply: true,
      supportsPlan: true,
      targetSystems: ["google.groups"],
    },
    async buildPlan(input) {
      const state = await loadInputState(
        dependencies.client,
        protectedEmails,
        protectedIds,
        input,
      );
      const details = exactDetails(input, state.snapshot);
      return {
        applicable: true,
        changes:
          state.phase === "pending"
            ? [
                {
                  actionId: ACTION_ID,
                  after: await expectedManagedAfter(details, state.snapshot),
                  before: state.managed,
                  confirmationCounts: { googleGroupRenames: 1 },
                  details,
                  display: `Rename ${input.oldEmail} to ${input.newEmail}`,
                  kind: "change",
                  reason:
                    "The exact immutable group and collision-free target were reviewed; preserve settings and direct memberships while changing only its primary email.",
                  resource: { id: details.googleGroupId, type: "google-group" },
                  risk: "high",
                },
              ]
            : [],
        diagnostics: [],
        sourceFingerprints: await fingerprints(details, state.snapshot),
      };
    },
    async readSourceFingerprints(input) {
      const state = await loadInputState(
        dependencies.client,
        protectedEmails,
        protectedIds,
        input,
      );
      return fingerprints(exactDetails(input, state.snapshot), state.snapshot);
    },
    async readManagedSlice(change) {
      const state = await loadDetailsState(
        dependencies.client,
        protectedEmails,
        protectedIds,
        change.details,
      );
      return state.managed;
    },
    async applyChange(change) {
      const execution = await withResourceLease(
        dependencies.leaseRepository,
        GOOGLE_GROUP_MUTATION_RESOURCE_LEASE_KEY,
        APPLY_LEASE_MS,
        async (lease) => {
          await dependencies.leaseRepository.assertActive(
            lease,
            APPLY_MIN_HEADROOM_MS,
          );
          const before = await loadDetailsState(
            dependencies.client,
            protectedEmails,
            protectedIds,
            change.details,
            lease.expiresAtMs - APPLY_MIN_HEADROOM_MS,
          );
          if (before.phase === "converged") return;
          if (!sameJson(before.managed, change.before)) {
            throw new Error("google_group_rename_reviewed_snapshot_drift");
          }
          await dependencies.leaseRepository.assertActive(
            lease,
            APPLY_MIN_HEADROOM_MS,
          );
          await dependencies.client.renameExact(
            change.details,
            before.snapshot,
            crypto.randomUUID(),
            lease.expiresAtMs - APPLY_MIN_HEADROOM_MS,
          );
          await dependencies.leaseRepository.assertActive(lease);
          const after = await loadDetailsState(
            dependencies.client,
            protectedEmails,
            protectedIds,
            change.details,
            lease.expiresAtMs - APPLY_MIN_HEADROOM_MS,
          );
          await dependencies.leaseRepository.assertActive(lease);
          if (
            after.phase !== "converged" ||
            !isExactRenameReadback(
              change.details,
              before.snapshot,
              after.snapshot,
            ) ||
            !sameJson(after.managed, change.after)
          ) {
            throw new Error("google_group_rename_readback_failed");
          }
        },
      );
      if (execution.kind === "busy")
        throw new Error("google_group_rename_busy");
    },
  });
}

async function loadInputState(
  client: IGoogleGroupRenameClient,
  protectedEmails: ReadonlySet<string>,
  protectedIds: ReadonlySet<string>,
  input: GoogleGroupRenameInput,
): Promise<ExactRenameState> {
  try {
    if (
      protectedEmails.has(input.oldEmail) ||
      protectedEmails.has(input.newEmail)
    ) {
      throw new Error("google_group_rename_protected_group");
    }
    const snapshot = await client.readSnapshot(input, crypto.randomUUID());
    if (protectedIds.has(snapshot.group.id))
      throw new Error("google_group_rename_protected_group");
    return await classifyState(input, snapshot);
  } catch (cause) {
    if (cause instanceof OperationSourceError) throw cause;
    if (cause instanceof GoogleGroupRenameSourceError) {
      throw new OperationSourceError(
        `google-group-exact-rename.${cause.stage}`,
        { cause },
      );
    }
    throw new OperationSourceError("google-group-exact-rename", { cause });
  }
}

async function loadDetailsState(
  client: IGoogleGroupRenameClient,
  protectedEmails: ReadonlySet<string>,
  protectedIds: ReadonlySet<string>,
  details: GoogleGroupRenameDetails,
  deadlineAt?: number,
): Promise<ExactRenameState> {
  try {
    if (
      protectedIds.has(details.googleGroupId) ||
      protectedEmails.has(details.oldEmail) ||
      protectedEmails.has(details.newEmail)
    ) {
      throw new Error("google_group_rename_protected_group");
    }
    const snapshot = await client.readSnapshot(
      details,
      crypto.randomUUID(),
      deadlineAt,
    );
    if (snapshot.group.id !== details.googleGroupId) {
      throw new Error("google_group_rename_immutable_id_drift");
    }
    return await classifyState(details, snapshot);
  } catch (cause) {
    if (cause instanceof OperationSourceError) throw cause;
    if (cause instanceof GoogleGroupRenameSourceError) {
      throw new OperationSourceError(
        `google-group-exact-rename.${cause.stage}`,
        { cause },
      );
    }
    throw new OperationSourceError("google-group-exact-rename", { cause });
  }
}

async function classifyState(
  input: GoogleGroupRenameInput,
  snapshot: GoogleGroupRenameSnapshot,
): Promise<ExactRenameState> {
  const currentEmail = snapshot.group.email.toLowerCase();
  let phase: ExactRenameState["phase"];
  if (currentEmail === input.oldEmail) {
    if (snapshot.collision !== null)
      throw new Error("google_group_rename_target_collision");
    phase = "pending";
  } else if (currentEmail === input.newEmail) {
    if (
      snapshot.collision?.id !== snapshot.group.id ||
      snapshot.collision.email.toLowerCase() !== input.newEmail
    ) {
      throw new Error("google_group_rename_converged_lookup_mismatch");
    }
    phase = "converged";
  } else {
    throw new Error("google_group_rename_primary_email_drift");
  }
  return { managed: await managedState(snapshot), phase, snapshot };
}

function exactDetails(
  input: GoogleGroupRenameInput,
  snapshot: GoogleGroupRenameSnapshot,
): GoogleGroupRenameDetails {
  return GoogleGroupRenameDetailsSchema.parse({
    ...input,
    googleGroupId: snapshot.group.id,
  });
}

async function managedState(
  snapshot: GoogleGroupRenameSnapshot,
): Promise<JsonValue> {
  return {
    collisionGroupId: snapshot.collision?.id ?? null,
    email: snapshot.group.email.toLowerCase(),
    googleGroupId: snapshot.group.id,
    membersFingerprint: await sha256Hex(snapshot.members),
    settingsFingerprint: await sha256Hex(snapshot.settings),
  };
}

async function expectedManagedAfter(
  input: GoogleGroupRenameDetails,
  snapshot: GoogleGroupRenameSnapshot,
): Promise<JsonValue> {
  return managedState({
    ...snapshot,
    collision: { email: input.newEmail, id: input.googleGroupId },
    group: {
      ...snapshot.group,
      email: input.newEmail,
      id: input.googleGroupId,
    },
  });
}

async function fingerprints(
  input: GoogleGroupRenameDetails,
  snapshot: GoogleGroupRenameSnapshot,
) {
  return [
    {
      authority: "google-directory-and-groups-settings",
      resourceId: input.googleGroupId,
      resourceType: "google-group-rename-snapshot",
      // The primary email and target lookup are the operation's managed slice: they must move
      // from before to after so a signed APPLY replay can converge without another PATCH.
      version: await sha256Hex({
        googleGroupId: snapshot.group.id,
        metadata: snapshot.group.metadata,
        members: snapshot.members,
        settings: snapshot.settings,
      }),
    },
  ];
}
