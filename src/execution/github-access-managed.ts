import { dequal } from "dequal";
import { z } from "zod";

import { contentHash } from "../github-access-audit/content-hash.ts";
import type { GitHubAccessSnapshot } from "../github-access-audit/git-hub-access-audit-client.ts";
import type { GoogleAuthoritySnapshot } from "../github-access-audit/google-contracts.ts";
import type { ReviewedGitHubDirectGrantRetention } from "../github-access-audit/reviewed-direct-grants.ts";
import {
  isReviewedGitHubTeamMembership,
  type ReviewedGitHubTeamMembership,
} from "../github-access-audit/reviewed-team-memberships.ts";
import type { EmployeeEntitlementAuthority } from "../identity-provisioning/employee-entitlement-policy.ts";
import { GitHubOrganizationSnapshotPort } from "../identity-provisioning/git-hub-organization-snapshot-port.ts";
import {
  type GitHubAuthorityProjection,
  projectGitHubOrganizationAuthority,
} from "../identity-provisioning/github-authority-projector.ts";
import {
  DryRunGitHubOrganizationConnector,
  executeGitHubOrganizationOperation,
  type GitHubDesiredAuthorityRefresh,
  type GitHubDesiredOrganizationAccess,
  GitHubDesiredOrganizationAccessSchema,
  type GitHubObservedOrganizationAccount,
  GitHubObservedOrganizationAccountSchema,
  type GitHubOrganizationPort,
  GitHubOrganizationProvisioningPlanSchema,
  type GitHubOrganizationWriteContext,
  planGitHubOrganizationAccess,
  readOnlyGitHubOrganizationPort,
  sameGitHubDesiredAuthority,
} from "../identity-provisioning/github-organization-connector.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { type JsonValue, JsonValueSchema } from "../operations/schemas.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";

const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const GITHUB_AUTHORITY_FINGERPRINT_UNAVAILABLE =
  "source_authority_fingerprint_unavailable";
const GITHUB_INVITATION_DOWNSTREAM_STATE =
  "requires-separate-saml-and-team-plan";
const GITHUB_MANAGED_TEAM_ACCESS_SNAPSHOT_INCOMPLETE =
  "github_managed_team_access_snapshot_incomplete";
const GITHUB_WRITER_AUTHORITY_DRIFT =
  "workspace_directory_github_access_writer_authority_drift";
const ConfigSchema = z.strictObject({
  maxChanges: z.literal(1),
  organizationId: z.string().regex(/^[1-9]\d*$/u),
  organizationLogin: z.string().trim().min(1),
  rootGroupEmail: z.email(),
  token: z.string().trim().min(1),
});

type GitHubBranch = WorkspaceDirectoryPlan["branches"][3];
type ManagedGitHubBranch = Extract<GitHubBranch, { execution: "managed" }>;
type NormalizedProviderPlan =
  ManagedGitHubBranch["accountPlans"][number]["plan"];

export type ManagedGitHubAccessConfig = z.input<typeof ConfigSchema>;

export interface ManagedGitHubAccessPolicy {
  readonly employeeEntitlementAuthority: EmployeeEntitlementAuthority;
  readonly excludedGroupEmails: readonly string[];
  readonly reviewedDirectGrantRetentions?: readonly ReviewedGitHubDirectGrantRetention[];
  readonly reviewedTeamMemberships?: readonly ReviewedGitHubTeamMembership[];
  readonly teamMappings: Readonly<Record<string, string>>;
  readonly teamPins?: Readonly<Record<string, number>>;
  readonly unmanagedGithubTeams: readonly string[];
}

interface ManagedGitHubAccessDependencies {
  readonly port?: GitHubOrganizationPort;
}

interface PlannedGitHubAccounts {
  readonly accountPlans: ManagedGitHubBranch["accountPlans"];
  readonly desiredByUserId: Map<string, GitHubDesiredOrganizationAccess>;
  readonly observedByUserId: Map<string, GitHubObservedOrganizationAccount>;
}

export interface CapturedManagedGitHubAccess {
  readonly branch: ManagedGitHubBranch;
  readonly desiredByUserId: ReadonlyMap<
    string,
    GitHubDesiredOrganizationAccess
  >;
  readonly observedByUserId: ReadonlyMap<
    string,
    GitHubObservedOrganizationAccount
  >;
  readonly selectedDesired: GitHubDesiredOrganizationAccess | null;
}

export async function captureManagedGitHubAccess(
  users: readonly GoogleDirectoryUser[],
  google: GoogleAuthoritySnapshot,
  github: GitHubAccessSnapshot,
  rawConfig: ManagedGitHubAccessConfig,
  policy: ManagedGitHubAccessPolicy,
  dependencies: ManagedGitHubAccessDependencies = {},
): Promise<ManagedGitHubBranch> {
  const captured = await captureManagedGitHubAccessState(
    users,
    google,
    github,
    rawConfig,
    policy,
    dependencies,
  );
  return captured.branch;
}

export async function captureManagedGitHubAuthorityFingerprint(
  users: readonly GoogleDirectoryUser[],
  google: GoogleAuthoritySnapshot,
  rawConfig: ManagedGitHubAccessConfig,
  policy: ManagedGitHubAccessPolicy,
): Promise<string> {
  const config = ConfigSchema.parse(rawConfig);
  await captureStage("source_authority_projection_unavailable", () =>
    projectAuthority(users, google, config.rootGroupEmail, policy),
  );
  return captureStage(GITHUB_AUTHORITY_FINGERPRINT_UNAVAILABLE, () =>
    fingerprintManagedGitHubAuthority(
      users,
      google,
      config.rootGroupEmail,
      policy,
    ),
  );
}

export async function captureManagedGitHubAccessState(
  users: readonly GoogleDirectoryUser[],
  google: GoogleAuthoritySnapshot,
  github: GitHubAccessSnapshot,
  rawConfig: ManagedGitHubAccessConfig,
  policy: ManagedGitHubAccessPolicy,
  dependencies: ManagedGitHubAccessDependencies = {},
): Promise<CapturedManagedGitHubAccess> {
  const config = ConfigSchema.parse(rawConfig);
  const projection = await captureStage(
    "source_authority_projection_unavailable",
    () => projectAuthority(users, google, config.rootGroupEmail, policy),
  );
  const diagnostics = projectionDiagnostics(projection, google);
  const port = await captureStage("source_snapshot_port_unavailable", () =>
    Promise.resolve(
      dependencies.port ??
        new GitHubOrganizationSnapshotPort(github, {
          ...(!(policy.teamPins === undefined) && {
            managedTeamPins: policy.teamPins,
          }),
          managedTeamSlugs: projection.managedTeamSlugs,
          organizationId: config.organizationId,
          organizationLogin: config.organizationLogin,
        }),
    ),
  );
  const planned = projection.complete
    ? await captureStage("source_account_planning_unavailable", () =>
        planAccounts(projection, port, policy),
      )
    : {
        accountPlans: [] satisfies ManagedGitHubBranch["accountPlans"],
        desiredByUserId: new Map<string, GitHubDesiredOrganizationAccess>(),
        observedByUserId: new Map<string, GitHubObservedOrganizationAccount>(),
      };
  const { accountPlans } = planned;
  for (const account of accountPlans) {
    if (account.plan.kind !== "blocked") continue;
    diagnostics.push({
      code: "github_provider_plan_blocked",
      message: `${account.googleUserId}: ${account.plan.blockers.map(({ code }) => code).join(", ")}`,
      severity: "warning",
    });
  }
  const selectedOperation = diagnostics.some(
    ({ severity }) => severity === "blocker",
  )
    ? null
    : selectOneOperation(accountPlans);
  const teamAccessHash = await captureStage(
    "source_team_fingerprint_unavailable",
    () =>
      fingerprintManagedGitHubTeamAccess(github, projection.managedTeamSlugs),
  );
  const stablePlan = {
    accountPlans,
    managedTeamSlugs: projection.managedTeamSlugs,
    organizationId: config.organizationId,
    organizationLogin: config.organizationLogin.toLowerCase(),
    selectedOperation,
    teamAccessHash,
  };
  const stableHashPlan = {
    ...stablePlan,
    accountPlans: accountPlans.map((account) => ({
      ...account,
      plan: { ...account.plan, desired: stableDesired(account.plan.desired) },
    })),
    selectedOperation:
      selectedOperation === null
        ? null
        : {
            ...selectedOperation,
            desired: stableDesired(selectedOperation.desired),
          },
  };
  const branch: ManagedGitHubBranch = {
    ...stablePlan,
    authorityHash: await captureStage(
      GITHUB_AUTHORITY_FINGERPRINT_UNAVAILABLE,
      () =>
        fingerprintManagedGitHubAuthority(
          users,
          google,
          config.rootGroupEmail,
          policy,
        ),
    ),
    branchId: "github-access",
    contentHash: Sha256Schema.parse(await contentHash(stableHashPlan)),
    diagnostics: [
      ...diagnostics,
      {
        code: "managed_exact_plan_apply",
        message:
          "GitHub access selects at most one signed operation and verifies source, target, immutable identity, organization pins, and provider readback.",
        severity: "info",
      },
    ],
    execution: "managed",
    killSwitchEngaged: false,
  };
  return {
    branch,
    desiredByUserId: planned.desiredByUserId,
    observedByUserId: planned.observedByUserId,
    selectedDesired:
      selectedOperation === null
        ? null
        : (planned.desiredByUserId.get(selectedOperation.googleUserId) ?? null),
  };
}

async function captureStage<T>(
  code: string,
  capture: () => Promise<T>,
): Promise<T> {
  try {
    return await capture();
  } catch (error) {
    throw new Error(code, { cause: error });
  }
}

/*
 * Fingerprints the complete effective-access surface connected to managed teams.
 * Parent and child teams are included because nesting changes inherited access.
 */
export async function fingerprintManagedGitHubTeamAccess(
  github: GitHubAccessSnapshot,
  managedTeamSlugs: readonly string[],
): Promise<string> {
  assertCompleteGitHubAccessSnapshot(github);
  const { relevantTeamIds, teamsById } = indexRelevantGitHubTeams(
    github,
    managedTeamSlugs,
  );
  expandGitHubTeamClosure(github, teamsById, relevantTeamIds);
  const organization = github.organization;
  if (organization === null)
    throw new Error(GITHUB_MANAGED_TEAM_ACCESS_SNAPSHOT_INCOMPLETE);
  return Sha256Schema.parse(
    await contentHash({
      organization: {
        defaultRepositoryPermission:
          organization["default_repository_permission"] ?? null,
        id: organization.id,
        login: organization.login.toLowerCase(),
      },
      repositoryGrants: github.repositories.flatMap((repository) =>
        repository.teamGrants
          .filter(({ id }) => relevantTeamIds.has(id))
          .map((grant) => ({
            archived: repository.archived,
            fullName: repository["full_name"],
            permission: grant.permission,
            repositoryId: repository.id,
            teamId: grant.id,
            teamSlug: grant.slug,
            visibility: repository.visibility,
          })),
      ),
      teams: [...relevantTeamIds].flatMap((teamId) => {
        const team = teamsById.get(teamId);
        return team === undefined
          ? []
          : {
              directMembers: team.directMembers.map(({ id, inherited }) => ({
                id,
                inherited: inherited ?? false,
              })),
              id: team.id,
              maintainers: team.maintainers.map(({ id, inherited }) => ({
                id,
                inherited: inherited ?? false,
              })),
              name: team.name,
              parent: team.parent,
              privacy: team.privacy,
              slug: team.slug,
            };
      }),
    }),
  );
}

function assertCompleteGitHubAccessSnapshot(
  github: GitHubAccessSnapshot,
): void {
  if (
    github.organization === null ||
    github.errors.some(({ capability }) => capability !== "scim_identities")
  ) {
    throw new Error(GITHUB_MANAGED_TEAM_ACCESS_SNAPSHOT_INCOMPLETE);
  }
}

function indexRelevantGitHubTeams(
  github: GitHubAccessSnapshot,
  managedTeamSlugs: readonly string[],
) {
  const teamsById = new Map(github.teams.map((team) => [team.id, team]));
  const configuredSlugs = new Set(managedTeamSlugs);
  const managedTeams = github.teams.filter(({ slug }) =>
    configuredSlugs.has(slug),
  );
  const observedSlugs = new Set(managedTeams.map(({ slug }) => slug));
  if (
    managedTeams.length !== configuredSlugs.size ||
    observedSlugs.size !== managedTeams.length ||
    teamsById.size !== github.teams.length
  ) {
    throw new Error(GITHUB_MANAGED_TEAM_ACCESS_SNAPSHOT_INCOMPLETE);
  }
  return {
    relevantTeamIds: new Set(managedTeams.map(({ id }) => id)),
    teamsById,
  };
}

function expandGitHubTeamClosure(
  github: GitHubAccessSnapshot,
  teamsById: ReadonlyMap<number, GitHubAccessSnapshot["teams"][number]>,
  relevantTeamIds: Set<number>,
): void {
  let expanded = true;
  while (expanded) {
    expanded = false;
    for (const team of github.teams) {
      if (
        relevantTeamIds.has(team.id) &&
        team.parent !== null &&
        !relevantTeamIds.has(team.parent.id)
      ) {
        if (!teamsById.has(team.parent.id)) {
          throw new Error(GITHUB_MANAGED_TEAM_ACCESS_SNAPSHOT_INCOMPLETE);
        }
        relevantTeamIds.add(team.parent.id);
        expanded = true;
      }
      if (
        team.parent !== null &&
        relevantTeamIds.has(team.parent.id) &&
        !relevantTeamIds.has(team.id)
      ) {
        relevantTeamIds.add(team.id);
        expanded = true;
      }
    }
  }
}

async function fingerprintManagedGitHubAuthority(
  users: readonly GoogleDirectoryUser[],
  google: GoogleAuthoritySnapshot,
  rootGroupEmail: string,
  policy: ManagedGitHubAccessPolicy,
) {
  return Sha256Schema.parse(
    await contentHash({
      groups: google.groups,
      memberships: google.memberships,
      policy,
      rootGroupEmail,
      users: users.map((user) => ({
        archived: user.archived ?? false,
        deletionTime: user.deletionTime ?? "",
        github: user.customSchemas?.SarjIdentity ?? {},
        id: user.id,
        primaryEmail: user.primaryEmail,
        suspended: user.suspended ?? false,
      })),
    }),
  );
}

export interface ManagedGitHubSourceAuthority {
  readonly google: GoogleAuthoritySnapshot;
  readonly policy: ManagedGitHubAccessPolicy;
  readonly rootGroupEmail: string;
}

export function sameManagedGitHubSelection(
  current: ManagedGitHubBranch["selectedOperation"],
  expected: ManagedGitHubBranch["selectedOperation"],
): boolean {
  if (current === null || expected === null) return current === expected;
  return (
    current.googleUserId === expected.googleUserId &&
    dequal(current.operation, expected.operation) &&
    sameGitHubDesiredAuthority(current.desired, expected.desired)
  );
}

export async function refreshManagedGitHubDesiredAuthority(
  branch: ManagedGitHubBranch,
  googleUserId: string,
  assertGoogleAuthority: () => Promise<readonly GoogleDirectoryUser[]>,
  captureState: (
    users: readonly GoogleDirectoryUser[],
  ) => Promise<CapturedManagedGitHubAccess>,
  captureSource: () => Promise<ManagedGitHubSourceAuthority>,
): Promise<GitHubDesiredOrganizationAccess> {
  const latest = await captureState(await assertGoogleAuthority());
  if (
    latest.branch.contentHash !== branch.contentHash ||
    !sameManagedGitHubSelection(
      latest.branch.selectedOperation,
      branch.selectedOperation,
    ) ||
    latest.selectedDesired?.subject.googleUserId !== googleUserId
  ) {
    throw new Error(GITHUB_WRITER_AUTHORITY_DRIFT);
  }
  const source = await captureSource();
  const finalUsers = await assertGoogleAuthority();
  await assertManagedGitHubSourceAuthority(
    branch,
    finalUsers,
    source.google,
    source.rootGroupEmail,
    source.policy,
  );
  return latest.selectedDesired;
}

async function assertManagedGitHubSourceAuthority(
  branch: ManagedGitHubBranch,
  users: readonly GoogleDirectoryUser[],
  google: GoogleAuthoritySnapshot,
  rootGroupEmail: string,
  policy: ManagedGitHubAccessPolicy,
) {
  const projection = await projectAuthority(
    users,
    google,
    rootGroupEmail,
    policy,
  );
  if (
    !projection.complete ||
    (await fingerprintManagedGitHubAuthority(
      users,
      google,
      rootGroupEmail,
      policy,
    )) !== branch.authorityHash
  ) {
    throw new Error(GITHUB_WRITER_AUTHORITY_DRIFT);
  }
}

export async function applyManagedGitHubAccess(
  branch: ManagedGitHubBranch,
  port: GitHubOrganizationPort,
  currentDesired: GitHubDesiredOrganizationAccess | null,
  refreshDesired: GitHubDesiredAuthorityRefresh,
  identityBudget?: IdentityWriteBudget,
  writeContext?: GitHubOrganizationWriteContext,
): Promise<string> {
  const selected = branch.selectedOperation;
  if (selected === null)
    return "GitHub organization access was already converged.";
  if (
    currentDesired === null ||
    !sameGitHubDesiredAuthority(currentDesired, selected.desired)
  ) {
    throw new Error("github_selected_desired_state_drift");
  }
  const receipt = await executeGitHubOrganizationOperation(
    port,
    currentDesired,
    selected.operation,
    refreshDesired,
    identityBudget,
    writeContext,
  );
  if (receipt.state === "invited") {
    return receipt.access === "pending-acceptance"
      ? "Created one reviewed GitHub organization invitation; acceptance, SAML, and team convergence remain pending."
      : "Created one reviewed GitHub organization invitation and verified active membership; SAML and team convergence remain separate.";
  }
  return `Applied and verified one reviewed GitHub ${selected.operation.kind} operation.`;
}

export async function readManagedGitHubTargetSlice(
  branch: ManagedGitHubBranch,
  port: GitHubOrganizationPort,
  desiredByUserId: CapturedManagedGitHubAccess["desiredByUserId"],
): Promise<JsonValue> {
  const selected = branch.selectedOperation;
  if (selected === null) return JsonValueSchema.parse([]);
  const currentDesired = desiredByUserId.get(selected.googleUserId) ?? null;
  if (
    currentDesired === null ||
    !sameGitHubDesiredAuthority(currentDesired, selected.desired)
  ) {
    return JsonValueSchema.parse({ state: "authority-drifted" });
  }
  if (selected.operation.kind === "invite-organization-member") {
    if (currentDesired.kind !== "present") {
      return invitationActionSlice(selected.googleUserId, "not-observed");
    }
    const github = currentDesired.subject.github;
    const observed = GitHubObservedOrganizationAccountSchema.parse(
      await port.observeAccount({
        githubLogin: github.githubLogin,
        githubUserId: github.githubUserId,
        primaryEmail: currentDesired.subject.primaryEmail,
      }),
    );
    const invitationPending = observed.pendingInvitations.some(
      ({ role }) => role === "direct_member",
    );
    const activeMember = observed.membership?.role === "member";
    return invitationActionSlice(
      selected.googleUserId,
      invitationPending || activeMember
        ? "provider-action-verified"
        : "not-observed",
    );
  }
  const planned = await new DryRunGitHubOrganizationConnector(
    readOnlyGitHubOrganizationPort(port),
  ).plan(currentDesired);
  return JsonValueSchema.parse([
    {
      googleUserId: selected.googleUserId,
      // The fresh desired authority was compared above, and the provider plan was
      // recomputed from fresh reads. Keep only its capture metadata pinned to the
      // signed slice so a later observation cannot manufacture target drift.
      plan: normalizeProviderPlan({ ...planned, desired: selected.desired }),
    },
  ]);
}

export function githubAccessBeforeSlice(
  branch: ManagedGitHubBranch,
): JsonValue {
  const selected = branch.selectedOperation;
  if (selected === null) return JsonValueSchema.parse([]);
  const account = branch.accountPlans.find(
    ({ googleUserId }) => googleUserId === selected.googleUserId,
  );
  if (account === undefined)
    throw new Error("github_selected_account_plan_missing");
  return JsonValueSchema.parse([account]);
}

export function githubAccessAfterSlice(branch: ManagedGitHubBranch): JsonValue {
  const selected = branch.selectedOperation;
  if (selected === null) return JsonValueSchema.parse([]);
  const account = branch.accountPlans.find(
    ({ googleUserId }) => googleUserId === selected.googleUserId,
  );
  if (account?.plan.kind !== "executable") {
    throw new Error("github_selected_account_plan_not_executable");
  }
  if (selected.operation.kind === "invite-organization-member") {
    return invitationActionSlice(
      account.googleUserId,
      "provider-action-verified",
    );
  }
  return JsonValueSchema.parse([
    {
      googleUserId: account.googleUserId,
      plan: {
        ...account.plan,
        operations: account.plan.operations.filter(
          (operation) => !dequal(operation, selected.operation),
        ),
      },
    },
  ]);
}

function invitationActionSlice(
  googleUserId: string,
  state: "not-observed" | "provider-action-verified",
): JsonValue {
  return JsonValueSchema.parse([
    {
      googleUserId,
      invitationAction: {
        downstreamAccess: GITHUB_INVITATION_DOWNSTREAM_STATE,
        kind: "invite-organization-member",
        state,
      },
    },
  ]);
}

async function projectAuthority(
  users: readonly GoogleDirectoryUser[],
  google: GoogleAuthoritySnapshot,
  rootGroupEmail: string,
  policy: ManagedGitHubAccessPolicy,
): Promise<GitHubAuthorityProjection> {
  if (!google.complete) {
    return {
      complete: false,
      diagnostics: google.issues.map((issue) => ({
        code: "identity-invalid" as const,
        detail: issue.message,
        level: "error" as const,
        subject: issue.code,
      })),
      managedTeamSlugs: Object.values(policy.teamMappings).toSorted(),
      plans: [],
    };
  }
  return projectGitHubOrganizationAuthority(
    {
      capturedAt: google.capturedAt,
      complete: true,
      groups: google.groups,
      memberships: google.memberships,
      users,
    },
    { ...policy, rootGroupEmail },
  );
}

async function planAccounts(
  projection: GitHubAuthorityProjection,
  port: GitHubOrganizationPort,
  policy: ManagedGitHubAccessPolicy,
): Promise<PlannedGitHubAccounts> {
  const readPort = readOnlyGitHubOrganizationPort(port);
  const accountPlans: ManagedGitHubBranch["accountPlans"] = [];
  const desiredByUserId = new Map<string, GitHubDesiredOrganizationAccess>();
  const observedByUserId = new Map<string, GitHubObservedOrganizationAccount>();
  for (const projected of projection.plans) {
    const observed = GitHubObservedOrganizationAccountSchema.parse(
      // eslint-disable-next-line no-await-in-loop -- Provider reads are intentionally serialized and bounded by the adapter.
      await readPort.observeAccount(
        projected.desired.kind === "present"
          ? {
              ...projected.desired.subject.github,
              primaryEmail: projected.desired.subject.primaryEmail,
            }
          : {
              ...projected.desired.target,
              primaryEmail: projected.desired.subject.primaryEmail,
            },
      ),
    );
    const retained = preserveReviewedMemberships(
      projected.desired,
      observed,
      policy.reviewedTeamMemberships ?? [],
    );
    const desired = attachReviewedDirectGrantRetention(retained, policy);
    const plan = planGitHubOrganizationAccess(desired, observed);
    accountPlans.push({
      googleUserId: projected.googleUserId,
      plan: normalizeProviderPlan(plan),
    });
    desiredByUserId.set(projected.googleUserId, desired);
    observedByUserId.set(projected.googleUserId, observed);
  }
  return { accountPlans, desiredByUserId, observedByUserId };
}

function attachReviewedDirectGrantRetention(
  desired: GitHubDesiredOrganizationAccess,
  policy: ManagedGitHubAccessPolicy,
): GitHubDesiredOrganizationAccess {
  if (desired.kind !== "present") return desired;
  const reviewed = policy.reviewedDirectGrantRetentions?.find(
    (entry) =>
      entry.googleUserId === desired.subject.googleUserId &&
      entry.primaryEmail === desired.subject.primaryEmail &&
      entry.githubUserId === desired.subject.github.githubUserId &&
      entry.githubLogin.toLowerCase() ===
        desired.subject.github.githubLogin.toLowerCase(),
  );
  return reviewed === undefined
    ? desired
    : GitHubDesiredOrganizationAccessSchema.parse({
        ...desired,
        reviewedDirectGrantRetention: reviewed,
      });
}

function preserveReviewedMemberships(
  desired: GitHubDesiredOrganizationAccess,
  observed: GitHubObservedOrganizationAccount,
  reviewed: readonly ReviewedGitHubTeamMembership[],
): GitHubDesiredOrganizationAccess {
  if (desired.kind !== "present" || observed.membership?.role !== "member")
    return desired;
  const preserved = new Set(
    observed.teamMemberships
      .filter(
        (membership) =>
          membership.role === "member" &&
          membership.state === "active" &&
          !membership.inherited &&
          desired.managedTeamSlugs.includes(membership.teamSlug) &&
          !desired.desiredTeamSlugs.includes(membership.teamSlug) &&
          isReviewedGitHubTeamMembership(
            { ...membership, googleUserId: desired.subject.googleUserId },
            reviewed,
          ),
      )
      .map((membership) => membership.teamSlug),
  );
  for (const slug of desired.desiredTeamSlugs) preserved.add(slug);
  return GitHubDesiredOrganizationAccessSchema.parse({
    ...desired,
    desiredTeamSlugs: [...preserved].toSorted((left, right) =>
      left.localeCompare(right),
    ),
  });
}

function normalizeProviderPlan(rawPlan: unknown): NormalizedProviderPlan {
  const plan = GitHubOrganizationProvisioningPlanSchema.parse(rawPlan);
  if (plan.kind === "blocked") {
    return { blockers: plan.blockers, desired: plan.desired, kind: plan.kind };
  }
  return {
    desired: plan.desired,
    kind: plan.kind,
    operations: plan.operations,
  };
}

function stableDesired(desired: GitHubDesiredOrganizationAccess) {
  const identity =
    desired.kind === "present" ? desired.subject.github : desired.target;
  return desired.kind === "present"
    ? {
        desiredTeamSlugs: desired.desiredTeamSlugs,
        githubLogin: identity.githubLogin,
        githubUserId: identity.githubUserId,
        googleUserId: desired.subject.googleUserId,
        kind: desired.kind,
        managedTeamSlugs: desired.managedTeamSlugs,
        reviewedDirectGrantRetention: desired.reviewedDirectGrantRetention,
      }
    : {
        githubLogin: identity.githubLogin,
        githubUserId: identity.githubUserId,
        googleUserId: desired.subject.googleUserId,
        kind: desired.kind,
      };
}

function selectOneOperation(
  accountPlans: ManagedGitHubBranch["accountPlans"],
): ManagedGitHubBranch["selectedOperation"] {
  let first: ManagedGitHubBranch["selectedOperation"] = null;
  for (const account of accountPlans) {
    if (account.plan.kind !== "executable") continue;
    const operation = account.plan.operations[0];
    if (operation === undefined) continue;
    const selected = {
      desired: account.plan.desired,
      googleUserId: account.googleUserId,
      operation,
    };
    first ??= selected;
    // Review-only removals stay visible without starving an independently authorized addition.
    if (
      operation.kind === "add-team-member" ||
      operation.kind === "invite-organization-member"
    )
      return selected;
  }
  return first;
}

function projectionDiagnostics(
  projection: GitHubAuthorityProjection,
  google: GoogleAuthoritySnapshot,
): ManagedGitHubBranch["diagnostics"] {
  return [
    ...google.issues.map((issue) => ({
      code: `github_google_${issue.code}`,
      message: issue.message,
      scope: { kind: "authority" as const },
      severity: "blocker" as const,
    })),
    ...projection.diagnostics.map((diagnostic) => ({
      code: `github_authority_${diagnostic.code}`,
      message: `${diagnostic.subject}: ${diagnostic.detail}`,
      ...(diagnostic.level === "error"
        ? {
            scope: {
              actionId: "workspace-directory.github-access" as const,
              kind: "action" as const,
            },
            severity: "blocker" as const,
          }
        : { severity: "warning" as const }),
    })),
  ];
}
