import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import {
  authoritativeGoogleDirectoryUserState,
  GoogleDirectoryUserIdSchema,
} from "../identity-lifecycle/contracts.ts";
import {
  type ResourceLeaseRepository,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import { sha256Hex } from "../operations/canonical.ts";
import {
  defineOperation,
  OperationSourceError,
  type RegisteredOperation,
} from "../operations/registry.ts";
import { type JsonValue, JsonValueSchema } from "../operations/schemas.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type {
  GoogleGroupPrivilegedMembershipRemoval,
  IGoogleGroupPrivilegedMembershipWriter,
  IGoogleGroupsClient,
} from "../org-sync/google-groups-client.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { isProtectedGoogleCleanupUser } from "../workspace-directory/google-group-cleanup-sync.ts";
import { GOOGLE_GROUP_MUTATION_RESOURCE_LEASE_KEY } from "./google-group-mutation-resource-lease-key.ts";

const EmailSchema = z.email().transform((value) => value.toLowerCase());
const LifecycleSchema = z.enum(["archived", "deleted", "suspended"]);
const RoleSchema = z.enum(["MANAGER", "OWNER"]);
const OwnerQuorumStateSchema = z.object({
  membership: z.literal("present"),
  ownerCount: z.number().int().min(2),
  role: z.literal("OWNER"),
});

export const PrivilegedGoogleGroupCleanupInputSchema = z.strictObject({
  googleGroupEmail: EmailSchema,
  googleGroupId: z.string().trim().min(1),
  googleUserId: GoogleDirectoryUserIdSchema,
  lifecycle: LifecycleSchema,
  memberEmail: EmailSchema,
  role: RoleSchema,
});
export type PrivilegedGoogleGroupCleanupInput = z.output<
  typeof PrivilegedGoogleGroupCleanupInputSchema
>;

const DetailsSchema = PrivilegedGoogleGroupCleanupInputSchema;
const ACTION_ID = "privileged-google-group-cleanup:remove";
const APPLY_LEASE_MS = 5 * 60 * 1000;
const APPLY_MIN_HEADROOM_MS = 30 * 1000;

type Directory = Required<
  Pick<IGoogleDirectoryClient, "getUserById" | "listDeletedUsers">
>;

export interface PrivilegedGoogleGroupCleanupDependencies {
  directory: Directory;
  groups: Pick<IGoogleGroupsClient, "listGroups">;
  leaseRepository: ResourceLeaseRepository;
  protectedGoogleUserIds: readonly string[];
  writer: IGoogleGroupPrivilegedMembershipWriter;
}

interface ExactState {
  authority: {
    email: string;
    googleUserId: string;
    lifecycle: PrivilegedGoogleGroupCleanupInput["lifecycle"];
  };
  group: { email: string; id: string };
  managed: JsonValue;
  present: boolean;
  target: GoogleGroupPrivilegedMembershipRemoval;
}

export function createPrivilegedGoogleGroupCleanupOperation(
  dependencies: PrivilegedGoogleGroupCleanupDependencies,
): RegisteredOperation {
  const protectedIds = new Set(dependencies.protectedGoogleUserIds);
  return defineOperation({
    name: "workspace-directory.privileged-google-group-cleanup",
    policyVersion: "2026-09-10.1",
    inputSchema: PrivilegedGoogleGroupCleanupInputSchema,
    detailsSchema: DetailsSchema,
    actionIds: [ACTION_ID],
    ttlSeconds: 300,
    metadata: {
      destructive: true,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["google.directory"],
      summary:
        "Remove one exact inactive Google Group manager or owner after strict safety checks.",
      supportsApply: true,
      supportsPlan: true,
      targetSystems: ["google.groups"],
    },
    async buildPlan(input) {
      const state = await loadExactState(dependencies, protectedIds, input);
      if (state.present) {
        await dependencies.writer.auditPrivilegedDirectMember(
          state.target,
          crypto.randomUUID(),
        );
      }
      return {
        applicable: true,
        changes: state.present
          ? [
              {
                actionId: ACTION_ID,
                after: { membership: "absent" },
                before: state.managed,
                confirmationCounts: { googlePrivilegedGroupMemberRemovals: 1 },
                details: input,
                display: `Remove ${input.memberEmail} as ${input.role} from ${input.googleGroupEmail}`,
                kind: "remove",
                reason:
                  "The exact immutable Google identity is inactive; privileged membership requires explicit reviewed removal.",
                resource: {
                  id: `${input.googleGroupId}:${input.googleUserId}:${input.role}`,
                  type: "google-group-privileged-membership",
                },
                risk: "high",
              },
            ]
          : [],
        diagnostics: [],
        sourceFingerprints: await fingerprints(state),
      };
    },
    async readSourceFingerprints(input) {
      return fingerprints(
        await loadExactState(dependencies, protectedIds, input),
      );
    },
    async readManagedSlice(change) {
      const state = await loadExactState(
        dependencies,
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
          const before = await loadExactState(
            dependencies,
            protectedIds,
            change.details,
          );
          if (!before.present) return;
          assertOwnerQuorum(before);
          await dependencies.leaseRepository.assertActive(
            lease,
            APPLY_MIN_HEADROOM_MS,
          );
          const result = await dependencies.writer.removePrivilegedDirectMember(
            before.target,
            crypto.randomUUID(),
            lease.expiresAtMs - APPLY_MIN_HEADROOM_MS,
          );
          if (!result.wrote) {
            throw new Error(
              "google_privileged_group_cleanup_writer_did_not_mutate",
            );
          }
          await dependencies.leaseRepository.assertActive(lease);
          const after = await loadExactState(
            dependencies,
            protectedIds,
            change.details,
          );
          if (after.present)
            throw new Error("google_privileged_group_cleanup_readback_failed");
        },
      );
      if (execution.kind === "busy")
        throw new Error("google_privileged_group_cleanup_busy");
    },
  });
}

function assertOwnerQuorum(state: ExactState): void {
  if (state.target.role !== "OWNER") return;
  if (!OwnerQuorumStateSchema.safeParse(state.managed).success) {
    throw new Error("google_privileged_group_cleanup_owner_quorum_required");
  }
}

async function loadExactState(
  dependencies: PrivilegedGoogleGroupCleanupDependencies,
  protectedIds: ReadonlySet<string>,
  input: PrivilegedGoogleGroupCleanupInput,
): Promise<ExactState> {
  try {
    if (protectedIds.has(input.googleUserId)) {
      throw new Error("google_privileged_group_cleanup_protected_user");
    }
    const runId = crypto.randomUUID();
    const [user, groups] = await Promise.all([
      resolveUser(
        dependencies.directory,
        GoogleUserIdSchema.parse(input.googleUserId),
        runId,
      ),
      dependencies.groups.listGroups(
        [input.googleGroupEmail],
        runId,
        undefined,
        false,
        true,
      ),
    ]);
    if (isProtectedGoogleCleanupUser(user)) {
      throw new Error("google_privileged_group_cleanup_protected_user");
    }
    const authority = authoritativeGoogleDirectoryUserState(user);
    const authorityEmail =
      authority.state === "deleted"
        ? authority.lastKnownPrimaryEmail
        : authority.primaryEmail;
    if (
      authority.googleUserId !== input.googleUserId ||
      authority.state !== input.lifecycle ||
      authorityEmail?.toLowerCase() !== input.memberEmail
    ) {
      throw new Error(
        "google_privileged_group_cleanup_identity_or_lifecycle_drift",
      );
    }
    const [group] = groups;
    if (
      groups.length !== 1 ||
      group?.id !== input.googleGroupId ||
      group.email.toLowerCase() !== input.googleGroupEmail
    ) {
      throw new Error("google_privileged_group_cleanup_group_drift");
    }
    const matches = group.members.filter(({ id }) => id === input.googleUserId);
    if (matches.length > 1)
      throw new Error("google_privileged_group_cleanup_duplicate_member");
    const [member] = matches;
    const target = {
      groupEmail: input.googleGroupEmail,
      groupId: input.googleGroupId,
      memberEmail: input.memberEmail,
      memberId: input.googleUserId,
      role: input.role,
    } satisfies GoogleGroupPrivilegedMembershipRemoval;
    if (member === undefined) {
      return {
        authority: {
          email: input.memberEmail,
          googleUserId: input.googleUserId,
          lifecycle: input.lifecycle,
        },
        group: { email: input.googleGroupEmail, id: input.googleGroupId },
        managed: { membership: "absent" },
        present: false,
        target,
      };
    }
    if (
      member.type !== "USER" ||
      member.email.toLowerCase() !== input.memberEmail ||
      member.role !== input.role
    ) {
      throw new Error("google_privileged_group_cleanup_member_drift");
    }
    const ownerCount = new Set(
      group.members.filter(({ role }) => role === "OWNER").map(({ id }) => id),
    ).size;
    return {
      authority: {
        email: input.memberEmail,
        googleUserId: input.googleUserId,
        lifecycle: input.lifecycle,
      },
      group: { email: input.googleGroupEmail, id: input.googleGroupId },
      managed:
        input.role === "OWNER"
          ? { membership: "present", ownerCount, role: input.role }
          : { membership: "present", role: input.role },
      present: true,
      target,
    };
  } catch (cause) {
    if (cause instanceof OperationSourceError) throw cause;
    throw new OperationSourceError("google-privileged-group-cleanup", {
      cause,
    });
  }
}

async function resolveUser(
  directory: Directory,
  googleUserId: z.output<typeof GoogleUserIdSchema>,
  runId: string,
): Promise<GoogleDirectoryUser> {
  const live = await directory.getUserById(googleUserId, runId);
  if (live !== null) return live;
  const deletedUsers = await directory.listDeletedUsers(runId);
  const matches = deletedUsers.filter(({ id }) => id === googleUserId);
  if (matches.length !== 1)
    throw new Error("google_privileged_group_cleanup_user_unresolved");
  const [deleted] = matches;
  if (deleted === undefined)
    throw new Error("google_privileged_group_cleanup_user_unresolved");
  return deleted;
}

async function fingerprints(state: ExactState) {
  const version = await sha256Hex(
    JsonValueSchema.parse({ authority: state.authority, group: state.group }),
  );
  return [
    {
      authority: "google-directory",
      resourceId: `${state.group.id}:${state.authority.googleUserId}`,
      resourceType: "privileged-group-membership-authority",
      version,
    },
  ];
}
