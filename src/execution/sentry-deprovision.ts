import { z } from "zod";

import { getWorkspaceSyncPolicy } from "../configuration.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import { GitHubDeprovisionGoogleAuthoritySnapshotSchema } from "../identity-provisioning/github-deprovision-google-authority-contract.ts";
import {
  fingerprintGoogleDeprovisionAuthority,
  googleDeprovisionIdentityEmails,
  validateGoogleDeprovisionAuthority,
} from "../identity-provisioning/google-deprovision-authority.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import type { IGoogleDirectoryClient } from "../org-sync/google-directory-client.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import {
  type ISentryWorkspaceClient,
  sentryMemberEmail,
  type SentryOrganizationMember,
} from "../workspace-directory/sentry-workspace-client.ts";
import {
  AuditedSentryWorkspacePlanSchema,
  type SentryWorkspaceAction,
} from "../workspace-directory/sentry-workspace-sync.ts";
import type { ReviewedActionState } from "./reviewed-action-context.ts";
import type { ReviewedSentryWorkspace } from "./reviewed-sentry-workspace.ts";
import { assertSentryWorkspaceAuthorityPins } from "./sentry-workspace-authority-pins.ts";

export interface SentryDeprovisionPorts {
  directory: Required<
    Pick<
      IGoogleDirectoryClient,
      "getUserById" | "listAllUsers" | "listDeletedUsers"
    >
  >;
  sentry: ISentryWorkspaceClient;
}
type Removal = Extract<
  SentryWorkspaceAction,
  { type: "remove-organization-member" }
>;
type Authority = Awaited<ReturnType<typeof captureGoogle>>;
const MAX_DETAIL_READS = 25;
const ProviderIdSchema = z.string().regex(/^\d{1,32}$/u);

export async function captureSentryDeprovisionPlan(
  ports: SentryDeprovisionPorts,
) {
  const authority = await captureGoogle(ports.directory);
  const inactive = authority.identities.filter(safeInactive);
  if (inactive.length === 0) return null;
  const inventory = await ports.sentry.listOrganizationMembers();
  assertUniqueMembers(inventory);
  const candidates = inventory
    .flatMap((member) => {
      const email = consistentMemberEmail(member);
      const user = inactive.find(
        (identity) =>
          email !== null &&
          googleDeprovisionIdentityEmails(identity).has(email),
      );
      return email === null || user === undefined || member.orgRole !== "member"
        ? []
        : {
            email,
            memberId: ProviderIdSchema.parse(member.id),
            googleUserId: user.id,
          };
    })
    .toSorted((left, right) =>
      `${left.googleUserId}:${left.memberId}`.localeCompare(
        `${right.googleUserId}:${right.memberId}`,
      ),
    );
  if (candidates.length === 0) return null;
  assertCompleteAuthority(authority);
  const providerAuthority = await ports.sentry.authorityBootstrap();
  if (!providerAuthority.actor.scopes.includes("member:admin"))
    throw conflict();
  assertActorAnchor(inventory, providerAuthority.actor.id);
  for (const candidate of candidates.slice(0, MAX_DETAIL_READS)) {
    // eslint-disable-next-line no-await-in-loop -- Bound exact detail reads and select one deterministic safe removal.
    const snapshot = await ports.sentry.snapshot([candidate.email]);
    const matches = snapshot.organizationMembers.filter(
      (entry) =>
        entry.id === candidate.memberId ||
        sentryMemberEmail(entry) === candidate.email,
    );
    const member = matches.length === 1 ? matches[0] : undefined;
    if (
      member?.id !== candidate.memberId ||
      consistentMemberEmail(member) !== candidate.email
    )
      throw conflict();
    if (!ordinaryMember(member, providerAuthority.actor.id)) continue;
    const action: Removal = {
      type: "remove-organization-member",
      email: candidate.email,
      memberId: candidate.memberId,
    };
    // eslint-disable-next-line no-await-in-loop -- Hash only the first eligible bounded removal.
    const planHash = await removalPlanHash(
      action,
      candidate.googleUserId,
      authority.fingerprint,
    );
    return {
      authorityFingerprint: authority.fingerprint,
      googleIdentities: [
        { email: candidate.email, googleUserId: candidate.googleUserId },
      ],
      providerAuthority,
      plan: AuditedSentryWorkspacePlanSchema.parse({
        activeGoogleMembers: [],
        actions: [action],
        planHash,
      }),
    };
  }
  if (candidates.length > MAX_DETAIL_READS)
    throw new Error("sentry_deprovision_detail_bound_exceeded");
  return null;
}

export async function readSentryDeprovision(
  ports: SentryDeprovisionPorts,
  reviewed: ReviewedSentryWorkspace,
): Promise<ReviewedActionState> {
  const action = removalAction(reviewed);
  const authority = await captureGoogle(ports.directory);
  const user = await assertReviewedAuthority(authority, reviewed);
  const bootstrap = await ports.sentry.authorityBootstrap();
  assertSentryWorkspaceAuthorityPins(reviewed.authorityPins, bootstrap);
  if (!bootstrap.actor.scopes.includes("member:admin")) throw conflict();
  const inventory = await ports.sentry.listOrganizationMembers();
  assertUniqueMembers(inventory);
  assertActorAnchor(inventory, bootstrap.actor.id);
  const emails = googleDeprovisionIdentityEmails(user);
  const matches = inventory.filter(
    (entry) =>
      entry.id === action.memberId ||
      emails.has(sentryMemberEmail(entry) ?? ""),
  );
  if (matches.length === 0) return "converged";
  if (
    matches.length !== 1 ||
    matches[0]?.id !== action.memberId ||
    consistentMemberEmail(matches[0]) !== action.email
  )
    return "drifted";
  const detailed = await ports.sentry.snapshot([action.email]);
  const exact = detailed.organizationMembers.filter(
    (entry) =>
      entry.id === action.memberId || sentryMemberEmail(entry) === action.email,
  );
  const member = exact.length === 1 ? exact[0] : undefined;
  return member?.id === action.memberId &&
    consistentMemberEmail(member) === action.email &&
    ordinaryMember(member, bootstrap.actor.id)
    ? "pending"
    : "drifted";
}

export async function applySentryDeprovision(
  ports: SentryDeprovisionPorts,
  reviewed: ReviewedSentryWorkspace,
  assertWriteAuthority: () => Promise<void>,
  assertFreshPlan: () => void,
): Promise<void> {
  const action = removalAction(reviewed);
  const before = await readSentryDeprovision(ports, reviewed);
  if (before === "converged") return;
  if (before !== "pending") throw conflict();
  let writeError: Error | undefined;
  try {
    await ports.sentry.removeOrganizationMember(action.memberId, async () => {
      await assertWriteAuthority();
      if ((await readSentryDeprovision(ports, reviewed)) !== "pending")
        throw conflict();
      const exact = await ports.directory.getUserById(
        reviewed.googleUserId,
        crypto.randomUUID(),
      );
      if (exact !== null) {
        if (
          exact.id !== reviewed.googleUserId ||
          !safeInactive(exact) ||
          !googleDeprovisionIdentityEmails(exact).has(action.email)
        )
          throw conflict();
      } else {
        const authority = await captureGoogle(ports.directory);
        const original = await assertReviewedAuthority(authority, reviewed);
        if (original.deletionTime === undefined) throw conflict();
      }
      await assertWriteAuthority();
      assertFreshPlan();
    });
  } catch (error) {
    writeError =
      error instanceof Error
        ? error
        : new Error("sentry_deprovision_write_failed");
  }
  if ((await readSentryDeprovision(ports, reviewed)) === "converged") return;
  if (writeError !== undefined) throw writeError;
  throw new Error("sentry_deprovision_readback_mismatch");
}

async function captureGoogle(directory: SentryDeprovisionPorts["directory"]) {
  const runId = crypto.randomUUID();
  const [users, deletedUsers] = await Promise.all([
    directory.listAllUsers(runId),
    directory.listDeletedUsers(runId),
  ]);
  const snapshot = GitHubDeprovisionGoogleAuthoritySnapshotSchema.parse({
    capturedAt: new Date().toISOString(),
    users,
    deletedUsers,
  });
  if (validateGoogleDeprovisionAuthority(snapshot).length !== 0)
    throw conflict();
  return {
    identities: [...snapshot.users, ...snapshot.deletedUsers],
    users: snapshot.users,
    fingerprint: await fingerprintGoogleDeprovisionAuthority(snapshot),
  };
}

function assertCompleteAuthority(authority: Authority): void {
  if (
    authority.users.length <
      getWorkspaceSyncPolicy().org.minimumGoogleParticipants ||
    getWorkspaceSyncPolicy().org.expectedRootGoogleUserIds.some(
      (id) =>
        !authority.users.some(
          (user) =>
            user.id === id && user.suspended !== true && user.archived !== true,
        ),
    )
  )
    throw conflict();
}

async function assertReviewedAuthority(
  authority: Authority,
  reviewed: ReviewedSentryWorkspace,
) {
  assertCompleteAuthority(authority);
  const action = removalAction(reviewed);
  const user = authority.identities.find(
    ({ id }) => id === reviewed.googleUserId,
  );
  if (
    authority.fingerprint !== reviewed.sourceAuthorityFingerprint ||
    user === undefined ||
    !safeInactive(user) ||
    !googleDeprovisionIdentityEmails(user).has(action.email) ||
    (await removalPlanHash(action, user.id, authority.fingerprint)) !==
      reviewed.expectedPlanHash
  )
    throw conflict();
  return user;
}

function safeInactive(user: GoogleDirectoryUser): boolean {
  return (
    (user.suspended === true ||
      user.archived === true ||
      user.deletionTime !== undefined) &&
    protectedIdentityBlocker({
      ...user,
      googleUserId: user.id,
      aliases: [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
    }) === undefined
  );
}

function ordinaryMember(
  member: SentryOrganizationMember,
  actorId: string,
): boolean {
  return (
    member.orgRole === "member" &&
    member.role === "member" &&
    member.user?.id !== actorId &&
    (member.pending || ProviderIdSchema.safeParse(member.user?.id).success) &&
    member.teamRoles.every(({ role }) => role === "contributor") &&
    new Set(member.teamRoles.map(({ teamSlug }) => teamSlug)).size ===
      member.teamRoles.length
  );
}

function consistentMemberEmail(
  member: Pick<SentryOrganizationMember, "email" | "user">,
): null | string {
  const email = sentryMemberEmail(member);
  return member.email !== undefined &&
    member.email !== null &&
    member.user?.email !== undefined &&
    member.email !== member.user.email
    ? null
    : email;
}

function assertUniqueMembers(
  members: readonly Pick<SentryOrganizationMember, "email" | "id" | "user">[],
): void {
  const emails = members
    .map(consistentMemberEmail)
    .filter((email): email is string => email !== null);
  if (
    emails.length !== members.length ||
    new Set(members.map(({ id }) => id)).size !== members.length ||
    new Set(emails).size !== emails.length
  )
    throw conflict();
}

function removalAction(reviewed: ReviewedSentryWorkspace): Removal {
  if (reviewed.action.type !== "remove-organization-member") throw conflict();
  return reviewed.action;
}

function removalPlanHash(
  action: Removal,
  googleUserId: string,
  sourceAuthorityFingerprint: string,
): Promise<string> {
  return contentHash({
    action,
    googleUserId,
    sourceAuthorityFingerprint,
    policy: "sentry-deprovision/v1",
  });
}

function conflict(): Error {
  return new Error("sentry_deprovision_authority_conflict");
}

function assertActorAnchor(
  members: readonly Pick<SentryOrganizationMember, "orgRole" | "user">[],
  actorId: string,
): void {
  const actors = members.filter((member) => member.user?.id === actorId);
  if (
    actors.length !== 1 ||
    !["owner", "manager", "admin"].includes(actors[0]?.orgRole ?? "")
  )
    throw conflict();
}
