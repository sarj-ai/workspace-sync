import { z } from "zod";

import {
  type DownstreamAccount,
  type GitHubAccessRead,
  normalizeEmail,
} from "../access-guard/model.ts";
import {
  GitHubLoginSchema,
  GitHubUserIdSchema,
} from "../catalog/identity-authority.ts";
import { correlateGitHubInvitation } from "../github/organization-membership-reader.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";

const OffboardingProviderSchema = z.enum([
  "github",
  "linear",
  "slack",
  "attio",
  "pagerduty",
  "ashby",
  "sentry",
  "trycomp",
]);
const OffboardingBlockerSchema = z.enum([
  "google_authority_unavailable",
  "google_identity_ambiguous",
  "google_identity_missing",
  "google_identity_active",
  "provider_read_failed",
  "provider_credentials_missing",
  "provider_auth_failed",
  "provider_request_rejected",
  "provider_endpoint_not_found",
  "provider_rate_limited",
  "provider_service_unavailable",
  "provider_timeout",
  "provider_network_failed",
  "provider_response_empty",
  "provider_schema_invalid",
  "provider_state_conflict",
  "provider_authority_unavailable",
  "provider_root_anchor_missing",
  "provider_inventory_incomplete",
  "snapshot_below_floor",
  "duplicate_identity",
  "github_identity_missing",
  "manual_deactivation_required",
  "deactivation_pending",
  "automation_disabled",
  "parent_mutation_safety_unresolved",
  "parent_schedule_unhealthy",
  "parent_schedule_health_unavailable",
  "unsupported",
]);
export const OffboardingProviderStatusSchema = z.strictObject({
  accountState: z.enum(["active", "inactive", "absent", "unknown"]),
  blocker: OffboardingBlockerSchema.nullable(),
  capability: z.enum(["automatic", "manual", "unsupported"]),
  observedAt: z.iso.datetime(),
  provider: OffboardingProviderSchema,
  verified: z.boolean(),
});
export const OffboardingStatusSchema = z
  .strictObject({
    complete: z.boolean(),
    googleState: z.enum([
      "active",
      "suspended",
      "archived",
      "deleted",
      "unknown",
    ]),
    googleUserId: z.string().nullable(),
    observedAt: z.iso.datetime(),
    providers: z.array(OffboardingProviderStatusSchema).length(8),
  })
  .meta({ id: "OffboardingStatus" });

type Provider = z.output<typeof OffboardingProviderSchema>;
type ProviderStatus = z.output<typeof OffboardingProviderStatusSchema>;
export type OffboardingStatus = z.output<typeof OffboardingStatusSchema>;
export interface OffboardingReader {
  automationEnabled?: boolean;
  capability: ProviderStatus["capability"];
  minimumAccounts: number;
  provider: Provider;
  read: () => Promise<GitHubAccessRead | readonly DownstreamAccount[]>;
}

export async function readOffboardingStatus(input: {
  googleUsers: () => Promise<readonly GoogleDirectoryUser[]>;
  minimumGoogleUsers: number;
  readers: readonly OffboardingReader[];
  rootGoogleUserIds: readonly string[];
  subject: string;
}): Promise<OffboardingStatus> {
  const observedAt = new Date().toISOString();
  let users: readonly GoogleDirectoryUser[];
  try {
    users = await input.googleUsers();
  } catch {
    return unknownReport(
      input.readers,
      observedAt,
      "google_authority_unavailable",
    );
  }
  if (
    users.length < input.minimumGoogleUsers ||
    input.rootGoogleUserIds.some(
      (id) =>
        !users.some(
          (candidate) =>
            candidate.id === id && sourceState(candidate) === "active",
        ),
    )
  )
    return unknownReport(
      input.readers,
      observedAt,
      "google_authority_unavailable",
    );
  const matches = users.filter(
    (candidate) =>
      candidate.id === input.subject ||
      emails(candidate).includes(normalizeEmail(input.subject)),
  );
  const user = matches[0];
  if (!user || matches.length !== 1)
    return unknownReport(
      input.readers,
      observedAt,
      user ? "google_identity_ambiguous" : "google_identity_missing",
    );
  if (hasConflictingIdentity(users, user)) {
    return unknownReport(
      input.readers,
      observedAt,
      "google_identity_ambiguous",
    );
  }
  const googleState = sourceState(user);
  const providers = await Promise.all(
    input.readers.map((reader) => readProvider(reader, user)),
  );
  return OffboardingStatusSchema.parse({
    complete:
      googleState !== "active" &&
      providers.every((provider) => provider.verified),
    googleState,
    googleUserId: user.id,
    observedAt,
    providers:
      googleState === "active"
        ? providers.map((provider) => ({
            ...provider,
            blocker: "google_identity_active",
            verified: false,
          }))
        : providers,
  });
}

function emails(user: GoogleDirectoryUser): string[] {
  return [
    user.primaryEmail,
    ...(user.aliases ?? []),
    ...(user.nonEditableAliases ?? []),
  ].map(normalizeEmail);
}

function unknownReport(
  readers: readonly OffboardingReader[],
  observedAt: string,
  blocker: ProviderStatus["blocker"],
): OffboardingStatus {
  return OffboardingStatusSchema.parse({
    complete: false,
    googleState: "unknown",
    googleUserId: null,
    observedAt,
    providers: readers.map((reader) => ({
      accountState: "unknown",
      blocker,
      capability: reader.capability,
      observedAt,
      provider: reader.provider,
      verified: false,
    })),
  });
}

function sourceState(
  user: GoogleDirectoryUser,
): OffboardingStatus["googleState"] {
  if (user.deletionTime) return "deleted";
  if (user.archived) return "archived";
  if (user.suspended) return "suspended";
  return "active";
}

function hasConflictingIdentity(
  users: readonly GoogleDirectoryUser[],
  user: GoogleDirectoryUser,
): boolean {
  const targetEmails = emails(user);
  const githubId = user.customSchemas?.SarjIdentity?.githubUserId;
  return users.some(
    (other) =>
      other !== user &&
      (other.id === user.id ||
        emails(other).some((email) => targetEmails.includes(email)) ||
        (githubId !== undefined &&
          other.customSchemas?.SarjIdentity?.githubUserId === githubId)),
  );
}

interface AccountEvidence {
  active?: boolean | undefined;
  blocker?: ProviderStatus["blocker"];
}
async function readProvider(
  reader: OffboardingReader,
  user: GoogleDirectoryUser,
): Promise<ProviderStatus> {
  const base = { capability: reader.capability, provider: reader.provider };
  function unknown(blocker: ProviderStatus["blocker"]): ProviderStatus {
    return {
      ...base,
      accountState: "unknown",
      blocker,
      observedAt: new Date().toISOString(),
      verified: false,
    };
  }
  if (reader.capability === "unsupported") return unknown("unsupported");
  try {
    const snapshot = await reader.read();
    const evidence =
      "invitations" in snapshot
        ? githubEvidence(snapshot, user, reader.minimumAccounts)
        : emailEvidence(snapshot, user, reader.minimumAccounts);
    if (evidence.blocker) return unknown(evidence.blocker);
    const pending = pendingBlocker(reader);
    return {
      ...base,
      accountState: verifiedState(evidence.active),
      blocker: evidence.active ? pending : null,
      observedAt: new Date().toISOString(),
      verified: evidence.active !== true,
    };
  } catch (error) {
    return unknown(providerReadBlocker(error));
  }
}

function providerReadBlocker(error: unknown): ProviderStatus["blocker"] {
  if (error instanceof z.ZodError) return "provider_schema_invalid";
  if (!(error instanceof Error)) return "provider_read_failed";
  switch (error.message) {
    case "offboarding_credentials_missing":
    case "ashby_offboarding_credentials_missing":
      return "provider_credentials_missing";
    case "ashby_offboarding_auth_failed":
    case "trycomp_people_http_401":
    case "trycomp_people_http_403":
    case "trycomp_people_list-members_http_401":
    case "trycomp_people_list-members_http_403":
      return "provider_auth_failed";
    case "ashby_offboarding_request_rejected":
      return "provider_request_rejected";
    case "ashby_offboarding_endpoint_not_found":
      return "provider_endpoint_not_found";
    case "ashby_offboarding_rate_limited":
      return "provider_rate_limited";
    case "ashby_offboarding_service_unavailable":
      return "provider_service_unavailable";
    case "ashby_offboarding_timeout":
      return "provider_timeout";
    case "ashby_offboarding_network_failed":
      return "provider_network_failed";
    case "ashby_offboarding_response_empty":
      return "provider_response_empty";
    case "ashby_offboarding_invalid_json":
      return "provider_schema_invalid";
    case "offboarding_provider_state_conflict":
      return "provider_state_conflict";
    case "offboarding_sentry_authority_unavailable":
      return "provider_authority_unavailable";
    case "ashby_offboarding_root_anchor_missing":
      return "provider_root_anchor_missing";
    case "ashby_offboarding_duplicate_identity":
      return "duplicate_identity";
    case "trycomp_people_count_mismatch":
    case "ashby_offboarding_cursor_cycle":
    case "ashby_offboarding_cursor_missing":
    case "ashby_offboarding_page_bound":
    case "ashby_offboarding_response_bound":
      return "provider_inventory_incomplete";
    default:
      return "provider_read_failed";
  }
}

function pendingBlocker(reader: OffboardingReader): ProviderStatus["blocker"] {
  if (reader.capability !== "automatic") return "manual_deactivation_required";
  return reader.automationEnabled === false
    ? "automation_disabled"
    : "deactivation_pending";
}

function emailEvidence(
  accounts: readonly DownstreamAccount[],
  user: GoogleDirectoryUser,
  minimum: number,
): AccountEvidence {
  if (accounts.length < minimum) return { blocker: "snapshot_below_floor" };
  if (
    new Set(accounts.map((account) => account.id)).size !== accounts.length ||
    new Set(accounts.map((account) => normalizeEmail(account.email))).size !==
      accounts.length
  ) {
    return { blocker: "duplicate_identity" };
  }
  const matched = accounts.filter((account) =>
    emails(user).includes(normalizeEmail(account.email)),
  );
  if (matched.length > 1) return { blocker: "duplicate_identity" };
  return { active: matched[0]?.active };
}

function githubEvidence(
  snapshot: GitHubAccessRead,
  user: GoogleDirectoryUser,
  minimum: number,
): AccountEvidence {
  if (snapshot.accounts.length < minimum)
    return { blocker: "snapshot_below_floor" };
  if (
    new Set(snapshot.accounts.map((account) => account.id)).size !==
      snapshot.accounts.length ||
    new Set(snapshot.invitations.map((invite) => invite.id)).size !==
      snapshot.invitations.length
  ) {
    return { blocker: "duplicate_identity" };
  }
  const id = GitHubUserIdSchema.safeParse(
    user.customSchemas?.SarjIdentity?.githubUserId,
  );
  if (!id.success) return { blocker: "github_identity_missing" };
  const login = GitHubLoginSchema.safeParse(
    user.customSchemas?.SarjIdentity?.githubLogin,
  );
  if (!login.success) {
    if (
      snapshot.accounts.some((account) => account.id === id.data) ||
      snapshot.invitations.some(
        (invite) =>
          invite.email &&
          !invite.invitee &&
          !invite.login &&
          emails(user).includes(normalizeEmail(invite.email)),
      )
    )
      return { active: true };
    return snapshot.invitations.length === 0
      ? {}
      : { blocker: "github_identity_missing" };
  }
  const correlations = new Set(
    snapshot.invitations.map((invite) => {
      const results = new Set(
        emails(user).map((primaryEmail) =>
          correlateGitHubInvitation(invite, {
            githubUserId: id.data,
            githubLogin: login.data,
            primaryEmail,
          }),
        ),
      );
      if (results.has("unresolved")) return "unresolved";
      return results.has("match") ? "match" : "unrelated";
    }),
  );
  if (correlations.has("unresolved"))
    return { blocker: "provider_read_failed" };
  const member = snapshot.accounts.some((account) => account.id === id.data);
  const invited = correlations.has("match");
  return { active: member || invited || undefined };
}

function verifiedState(
  active: boolean | undefined,
): ProviderStatus["accountState"] {
  if (active === undefined) return "absent";
  return active ? "active" : "inactive";
}
