import { z } from "zod";

import {
  isActiveGoogleUser,
  isInactiveGoogleUser,
} from "../google-workspace/user-lifecycle.ts";
import { linearSuspensionBlocker } from "./linear-suspension-blocker.ts";
import {
  type AccessDiagnostic,
  type AccessGuardAuditOptions,
  type AccessGuardConfig,
  AccessGuardConfigSchema,
  type AccessGuardPlan,
  AccessGuardPlanSchema,
  type AccessIssue,
  type DownstreamAccount,
  type GitHubAccessAccount,
  GitHubAccessAccountSchema,
  type GitHubAccessInvitation,
  type GoogleAccessUser,
  GoogleAccessUserSchema,
  normalizeEmail,
  type ProviderName,
  type ProviderSnapshot,
  ProviderSnapshotSchema,
} from "./model.ts";

const DiagnosticCodeSchema = z.string();

type PrimaryOrganizationResult =
  | { department?: string; kind: "one"; title?: string }
  | { kind: "invalid" }
  | { kind: "none" };

export const MAX_AUTOMATIC_LINEAR_SUSPENSIONS = 5;

export function computeAccessGuardPlan(
  input: AccessGuardAuditOptions & {
    config: unknown;
    googleUsers: unknown;
    providerSnapshots: unknown;
  },
): AccessGuardPlan {
  const config = AccessGuardConfigSchema.parse(input.config);
  const googleUsers = GoogleAccessUserSchema.array().parse(input.googleUsers);
  const providerSnapshots = ProviderSnapshotSchema.array().parse(
    input.providerSnapshots,
  );
  const diagnostics: AccessDiagnostic[] = [];
  const issues: AccessIssue[] = [];
  const actions: AccessGuardPlan["actions"] = [];
  const excluded = new Set(config.excludedGoogleUserIds);
  const roots = new Set(config.rootGoogleUserIds);
  const allowedEmptyDepartments = new Set(
    config.allowedEmptyDepartmentGoogleUserIds,
  );
  const allowedEmptyManagers = new Set(config.allowedEmptyManagerGoogleUserIds);
  const googleIds = new Map(googleUsers.map((user) => [user.id, user]));
  appendGoogleSnapshotDiagnostics(config, googleUsers, googleIds, diagnostics);
  const googleIndex = buildGoogleIndex(googleUsers, diagnostics);
  const googleGitHubIndex = buildGoogleGitHubIndex(googleUsers, diagnostics);
  const includedGoogleUsers = googleUsers.filter(
    (user) => !excluded.has(user.id),
  );
  const activeGooglePeople = includedGoogleUsers.filter(isActiveGoogleUser);

  for (const user of activeGooglePeople) {
    const issue = metadataIssue(
      user,
      roots,
      allowedEmptyDepartments,
      allowedEmptyManagers,
      googleIndex,
      diagnostics,
    );
    if (issue) issues.push(issue);
  }

  const snapshotCounts = providerSnapshotCounts(providerSnapshots);
  const duplicateProviders = appendProviderShapeDiagnostics(
    config.requiredProviders,
    snapshotCounts,
    diagnostics,
  );
  const providerAccounts = processProviderSnapshots(
    providerSnapshots,
    duplicateProviders,
    config.minimumProviderAccounts,
    {
      actions,
      diagnostics,
      googleGitHubIndex,
      googleIndex,
      issues,
      protectedGoogleUserIds: roots.union(excluded),
    },
  );
  const target = input.linearSuspensionTarget;
  if (target !== undefined && input.scheduledLinearSuspension === true)
    throw new Error("access_guard_linear_selection_conflict");
  let selectedActions = actions;
  if (input.scheduledLinearSuspension === true) {
    selectedActions = actions
      .toSorted((left, right) => left.accountId.localeCompare(right.accountId))
      .slice(0, 1);
  } else if (target !== undefined) {
    selectedActions = actions.filter(
      (action) =>
        action.accountId === target.accountId &&
        action.email === target.email &&
        action.googleUserId === target.googleUserId,
    );
  }
  enforceSuspensionCap(
    selectedActions,
    diagnostics,
    config.maxReviewedLinearSuspensions,
  );

  appendCoverageIssues(diagnostics, issues);

  issues.sort((left, right) => left.id.localeCompare(right.id));
  diagnostics.sort((left, right) => {
    const leftKey = `${left.provider ?? ""}:${left.code}:${JSON.stringify(left.context)}`;
    const rightKey = `${right.provider ?? ""}:${right.code}:${JSON.stringify(right.context)}`;
    return leftKey.localeCompare(rightKey);
  });
  selectedActions.sort((left, right) =>
    left.accountId.localeCompare(right.accountId),
  );
  return AccessGuardPlanSchema.parse({
    actions: selectedActions,
    diagnostics,
    issues,
    stats: {
      activeGooglePeople: activeGooglePeople.length,
      googleUsers: googleUsers.length,
      providerAccounts,
      inactiveGoogleUsers:
        includedGoogleUsers.filter(isInactiveGoogleUser).length,
    },
  });
}

interface GoogleEmailIndex {
  ambiguous: Set<string>;
  byEmail: Map<string, GoogleAccessUser>;
}

interface GoogleGitHubIndex {
  blocked: boolean;
  byLogin: Map<string, GoogleAccessUser>;
  byUserId: Map<string, GoogleAccessUser>;
}

function buildGoogleIndex(
  users: GoogleAccessUser[],
  diagnostics: AccessDiagnostic[],
): GoogleEmailIndex {
  const byEmail = new Map<string, GoogleAccessUser>();
  const ambiguous = new Set<string>();
  for (const user of users) {
    for (const email of new Set(allGoogleEmails(user))) {
      const existing = byEmail.get(email);
      if (existing && existing.id !== user.id) {
        ambiguous.add(email);
        byEmail.delete(email);
      } else if (!ambiguous.has(email)) {
        byEmail.set(email, user);
      }
    }
  }
  for (const email of [...ambiguous].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  )) {
    diagnostics.push({
      code: "ambiguous_google_email",
      context: { email },
      level: "error",
      message:
        "Google email or alias maps to more than one user; no downstream action is allowed",
    });
  }
  return { ambiguous, byEmail };
}

function allGoogleEmails(user: GoogleAccessUser): string[] {
  return [user.primaryEmail, ...user.aliases, ...user.nonEditableAliases].map(
    normalizeEmail,
  );
}

function buildGoogleGitHubIndex(
  users: GoogleAccessUser[],
  diagnostics: AccessDiagnostic[],
): GoogleGitHubIndex {
  const byLogin = new Map<string, GoogleAccessUser>();
  const byUserId = new Map<string, GoogleAccessUser>();
  let blocked = false;
  for (const user of users) {
    const identity = user.customSchemas?.SarjIdentity;
    if (!identity) continue;
    const hasLogin = identity.githubLogin !== undefined;
    const hasUserId = identity.githubUserId !== undefined;
    if (!hasLogin && !hasUserId) continue;
    const login = GitHubAccessAccountSchema.shape.login.safeParse(
      identity.githubLogin,
    );
    const userId = GitHubAccessAccountSchema.shape.id.safeParse(
      identity.githubUserId,
    );
    if (!hasLogin || !hasUserId || !login.success || !userId.success) {
      blocked = true;
      diagnostics.push({
        code: "invalid_google_github_identity",
        context: { "google_user_id": user.id },
        level: "error",
        message:
          "Google GitHub identity must contain one valid normalized login and one stable numeric user ID",
        provider: "github",
      });
      continue;
    }
    const loginOwner = byLogin.get(login.data);
    const userIdOwner = byUserId.get(userId.data);
    if (
      (loginOwner && loginOwner.id !== user.id) ||
      (userIdOwner && userIdOwner.id !== user.id)
    ) {
      blocked = true;
      diagnostics.push({
        code: "ambiguous_github_identity",
        context: { "google_user_id": user.id },
        level: "error",
        message:
          "A GitHub login or stable user ID maps to more than one Google user",
        provider: "github",
      });
      continue;
    }
    byLogin.set(login.data, user);
    byUserId.set(userId.data, user);
  }
  return { blocked, byLogin, byUserId };
}

function managerRelations(user: GoogleAccessUser): string[] {
  return user.relations
    .filter(
      (relation) => relation.type.toLocaleLowerCase("en-US") === "manager",
    )
    .flatMap((relation) =>
      relation.value ? [normalizeEmail(relation.value)] : [],
    );
}

function metadataIssue(
  user: GoogleAccessUser,
  roots: Set<string>,
  allowedEmptyDepartments: Set<string>,
  allowedEmptyManagers: Set<string>,
  googleIndex: GoogleEmailIndex,
  diagnostics: AccessDiagnostic[],
): AccessIssue | null {
  const missing = new Set<string>();
  appendOrganizationMetadata(
    user,
    allowedEmptyDepartments,
    missing,
    diagnostics,
  );
  appendManagerMetadata(
    user,
    roots,
    allowedEmptyManagers,
    googleIndex,
    missing,
    diagnostics,
  );

  const fields = [...missing].toSorted(
    (sortLeft, sortRight) =>
      Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
  );
  if (fields.length === 0) return null;
  const email = normalizeEmail(user.primaryEmail);
  return {
    details: { email, "missing_fields": fields.join(",") },
    googleUserId: user.id,
    id: `m:${user.id}:${fields.join("+")}`,
    kind: "missing_google_org_metadata",
    summary: `${email} is missing critical Google Workspace org metadata: ${fields.join(", ")}`,
  };
}

function appendManagerMetadata(
  user: GoogleAccessUser,
  roots: Set<string>,
  allowedEmptyManagers: Set<string>,
  googleIndex: GoogleEmailIndex,
  missing: Set<string>,
  diagnostics: AccessDiagnostic[],
): void {
  if (roots.has(user.id)) return;
  if (
    allowedEmptyManagers.has(user.id) &&
    !user.relations.some(
      (relation) => relation.type.toLocaleLowerCase("en-US") === "manager",
    )
  )
    return;
  const managers = managerRelations(user);
  if (managers.length === 1) {
    const managerEmail = managers[0];
    const manager = managerEmail
      ? googleIndex.byEmail.get(managerEmail)
      : undefined;
    if (!manager || isInactiveGoogleUser(manager)) missing.add("manager");
    return;
  }
  missing.add("manager");
  if (managers.length < 2) return;
  diagnostics.push({
    code: "invalid_google_org_shape",
    context: {
      "google_user_id": user.id,
      "manager_relations": managers.length,
    },
    level: "error",
    message: "Google user has more than one manager relation",
  });
}

function appendOrganizationMetadata(
  user: GoogleAccessUser,
  allowedEmptyDepartments: Set<string>,
  missing: Set<string>,
  diagnostics: AccessDiagnostic[],
): void {
  const organization = primaryOrganization(user);
  if (organization.kind === "invalid") {
    diagnostics.push({
      code: "invalid_google_org_shape",
      context: { "google_user_id": user.id },
      level: "error",
      message: "Google user has multiple primary organizations",
    });
    missing.add("department");
    return;
  }
  if (
    !allowedEmptyDepartments.has(user.id) &&
    (organization.kind === "none" || !organization.department)
  ) {
    missing.add("department");
  }
}

function primaryOrganization(
  user: GoogleAccessUser,
): PrimaryOrganizationResult {
  const primary = user.organizations.filter(
    (candidate) => candidate.primary === true,
  );
  if (primary.length > 1) return { kind: "invalid" };
  const organization = primary[0];
  if (!organization) return { kind: "none" };
  return {
    ...(!(organization.department === undefined) && {
      department: organization.department,
    }),
    kind: "one",
    ...(!(organization.title === undefined) && { title: organization.title }),
  };
}

function appendGoogleSnapshotDiagnostics(
  config: AccessGuardConfig,
  googleUsers: GoogleAccessUser[],
  googleIds: Map<string, GoogleAccessUser>,
  diagnostics: AccessDiagnostic[],
): void {
  if (googleIds.size !== googleUsers.length) {
    diagnostics.push({
      code: "invalid_google_org_shape",
      context: {
        "google_users": googleUsers.length,
        "unique_google_user_ids": googleIds.size,
      },
      level: "error",
      message: "Google Directory returned duplicate immutable user IDs",
    });
  }
  if (googleUsers.length < config.minimumGoogleUsers) {
    diagnostics.push({
      code: "invalid_google_org_shape",
      context: {
        "google_users": googleUsers.length,
        "minimum_google_users": config.minimumGoogleUsers,
      },
      level: "error",
      message:
        "Google Directory snapshot is below the configured population floor",
    });
  }
  appendRootDiagnostics(config.rootGoogleUserIds, googleIds, diagnostics);
  appendProtectedDepartureDiagnostics(
    config.protectedDepartedGoogleUserIds,
    googleIds,
    diagnostics,
  );
}

function appendRootDiagnostics(
  rootIds: string[],
  googleIds: Map<string, GoogleAccessUser>,
  diagnostics: AccessDiagnostic[],
): void {
  for (const rootId of rootIds) {
    const root = googleIds.get(rootId);
    if (!root || isInactiveGoogleUser(root)) {
      diagnostics.push({
        code: "invalid_google_org_shape",
        context: { "google_user_id": rootId },
        level: "error",
        message:
          "An expected Google Workspace reporting root is missing or inactive",
      });
      continue;
    }
    if (managerRelations(root).length === 0) continue;
    diagnostics.push({
      code: "invalid_google_org_shape",
      context: { "google_user_id": rootId },
      level: "error",
      message:
        "An expected Google Workspace reporting root unexpectedly has a manager",
    });
  }
}

function appendProtectedDepartureDiagnostics(
  protectedIds: string[],
  googleIds: Map<string, GoogleAccessUser>,
  diagnostics: AccessDiagnostic[],
): void {
  for (const protectedId of protectedIds) {
    const user = googleIds.get(protectedId);
    if (!user || isInactiveGoogleUser(user)) continue;
    diagnostics.push({
      code: "invalid_google_org_shape",
      context: { "google_user_id": protectedId },
      level: "error",
      message:
        "A protected departed Google account has been restored to active",
    });
  }
}

function appendCoverageIssues(
  diagnostics: AccessDiagnostic[],
  issues: AccessIssue[],
): void {
  const codesByProvider = new Map<ProviderName, Set<string>>();
  const googleValidationCodes = new Set<string>();
  for (const diagnostic of diagnostics) {
    if (diagnostic.level !== "error") continue;
    const errorCode = diagnostic.context["error_code"];
    const parsedCode = DiagnosticCodeSchema.safeParse(errorCode);
    const code = parsedCode.success ? parsedCode.data : diagnostic.code;
    if (!diagnostic.provider) {
      googleValidationCodes.add(code);
      continue;
    }
    const codes = codesByProvider.get(diagnostic.provider) ?? new Set<string>();
    codes.add(code);
    codesByProvider.set(diagnostic.provider, codes);
  }
  if (googleValidationCodes.size > 0) {
    const fingerprint = [...googleValidationCodes]
      .toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      )
      .join("+");
    issues.push({
      details: {
        "error_codes": [...googleValidationCodes]
          .toSorted(
            (sortLeft, sortRight) =>
              Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
          )
          .join(","),
      },
      id: `c:google:${fingerprint}`,
      kind: "coverage_failure",
      summary:
        "Google Workspace identity and org validation is incomplete; automatic writes are blocked",
    });
  }
  for (const [provider, codes] of codesByProvider) {
    const fingerprint = [...codes]
      .toSorted(
        (sortLeft, sortRight) =>
          Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
      )
      .join("+");
    issues.push({
      details: {
        "error_codes": [...codes]
          .toSorted(
            (sortLeft, sortRight) =>
              Number(sortLeft > sortRight) - Number(sortLeft < sortRight),
          )
          .join(","),
      },
      id: `c:${provider}:${fingerprint}`,
      kind: "coverage_failure",
      provider,
      summary: `${provider} access-audit coverage is incomplete; automatic writes are blocked`,
    });
  }
}

function providerSnapshotCounts(
  snapshots: ProviderSnapshot[],
): Map<ProviderName, number> {
  const counts = new Map<ProviderName, number>();
  for (const snapshot of snapshots) {
    counts.set(snapshot.provider, (counts.get(snapshot.provider) ?? 0) + 1);
  }
  return counts;
}

function appendProviderShapeDiagnostics(
  requiredProviders: ProviderName[],
  snapshotCounts: Map<ProviderName, number>,
  diagnostics: AccessDiagnostic[],
): Set<ProviderName> {
  for (const provider of requiredProviders) {
    if (snapshotCounts.has(provider)) continue;
    diagnostics.push({
      code: "provider_error",
      context: { "error_code": "required_provider_snapshot_missing" },
      level: "error",
      message: "Required provider supplied no snapshot; coverage is incomplete",
      provider,
    });
  }
  const duplicates = new Set<ProviderName>();
  for (const [provider, count] of snapshotCounts) {
    if (count < 2) continue;
    duplicates.add(provider);
    diagnostics.push({
      code: "provider_error",
      context: {
        "error_code": "duplicate_provider_snapshots",
        "snapshot_count": count,
      },
      level: "error",
      message:
        "Provider supplied more than one snapshot; the provider is fail-closed",
      provider,
    });
  }
  return duplicates;
}

interface ProviderProcessingContext {
  actions: AccessGuardPlan["actions"];
  diagnostics: AccessDiagnostic[];
  googleGitHubIndex: GoogleGitHubIndex;
  googleIndex: GoogleEmailIndex;
  issues: AccessIssue[];
  protectedGoogleUserIds: ReadonlySet<string>;
}

function providerCoverageLabel(provider: ProviderName): string {
  return provider === "github" ? "GitHub organization access" : provider;
}

function processProviderSnapshots(
  snapshots: ProviderSnapshot[],
  duplicates: Set<ProviderName>,
  minimumProviderAccounts: Partial<Record<ProviderName, number>>,
  context: ProviderProcessingContext,
): Partial<Record<ProviderName, number>> {
  const providerAccounts: Partial<Record<ProviderName, number>> = {};
  for (const snapshot of snapshots) {
    if (duplicates.has(snapshot.provider)) continue;
    if (!snapshot.ok) {
      if ("readiness" in snapshot) {
        context.diagnostics.push({
          code: "provider_readiness",
          context: snapshot.readiness,
          level: "error",
          message:
            "Provider tenant is observed but not safely pinned; no conclusions or writes were made",
          provider: "linear",
        });
      } else {
        context.diagnostics.push({
          code: "provider_error",
          context: { "error_code": snapshot.errorCode },
          level: "error",
          message:
            "Provider snapshot failed; no conclusions or writes were made for this provider",
          provider: snapshot.provider,
        });
      }
      continue;
    }
    providerAccounts[snapshot.provider] = snapshot.accounts.length;
    if (snapshot.provider === "github") {
      appendGitHubInvitationDiagnostics(
        snapshot.invitations,
        context.diagnostics,
      );
    }
    const minimum = minimumProviderAccounts[snapshot.provider] ?? 0;
    if (snapshot.accounts.length < minimum) {
      context.diagnostics.push({
        code: "provider_error",
        context: {
          "account_count": snapshot.accounts.length,
          "error_code": "provider_population_below_minimum",
          minimum,
        },
        level: "error",
        message:
          "Provider population is below its conservative safety floor; coverage is incomplete",
        provider: snapshot.provider,
      });
      continue;
    }
    if (snapshot.provider === "github") {
      processGitHubAccounts(snapshot.accounts, context);
      continue;
    }
    const index = uniqueProviderEmails(
      snapshot.provider,
      snapshot.accounts,
      context.diagnostics,
    );
    for (const [email, account] of index.byEmail) {
      processProviderAccount(
        snapshot.provider,
        email,
        account,
        index.blocked,
        context,
      );
    }
  }
  return providerAccounts;
}

function processProviderAccount(
  provider: ProviderName,
  email: string,
  account: DownstreamAccount,
  providerBlocked: boolean,
  context: ProviderProcessingContext,
): void {
  const google = context.googleIndex.byEmail.get(email);
  if (!google) {
    if (!account.active || context.googleIndex.ambiguous.has(email)) return;
    if (provider === "linear" && account.app === true) return;
    appendUnmatchedAccount(provider, email, account, context);
    return;
  }
  if (!account.active || isActiveGoogleUser(google)) return;
  appendInactiveAccount(
    provider,
    email,
    account,
    google,
    providerBlocked,
    context,
  );
}

function appendUnmatchedAccount(
  provider: ProviderName,
  email: string,
  account: DownstreamAccount,
  context: ProviderProcessingContext,
): void {
  context.issues.push({
    details: { "account_id": account.id, email },
    id: `u:${provider}:${account.id}`,
    kind: "active_downstream_without_google",
    provider,
    summary: `${email} is active in ${providerCoverageLabel(provider)} but has no Google Workspace identity`,
  });
  context.diagnostics.push({
    code: "unmatched_provider_account",
    context: { "account_id": account.id, email },
    level: "warning",
    message:
      "Active provider identity has no exact Google primary-email or unambiguous alias match",
    provider,
  });
}

function appendInactiveAccount(
  provider: ProviderName,
  email: string,
  account: DownstreamAccount,
  google: GoogleAccessUser,
  providerBlocked: boolean,
  context: ProviderProcessingContext,
): void {
  context.issues.push({
    details: { "account_id": account.id, email },
    googleUserId: google.id,
    id: `s:${provider}:${google.id}`,
    kind: "active_downstream_for_inactive_google",
    provider,
    summary: `${email} is inactive in Google Workspace but active in ${providerCoverageLabel(provider)}`,
  });
  if (
    provider !== "linear" ||
    providerBlocked ||
    context.googleIndex.ambiguous.has(email)
  )
    return;
  const protection =
    context.protectedGoogleUserIds.has(google.id) ||
    google.isAdmin !== false ||
    google.isDelegatedAdmin !== false
      ? "linear_protected_google_identity"
      : linearSuspensionBlocker(account, google.id, [
          google.primaryEmail,
          ...google.aliases,
          ...google.nonEditableAliases,
        ]);
  if (protection !== undefined) {
    context.diagnostics.push({
      code: "protected_linear_account",
      context: {
        "account_id": account.id,
        "google_user_id": google.id,
        reason: protection,
      },
      level: "error",
      message:
        "Linear suspension requires an unprotected human identity and complete nonprivileged role evidence",
      provider: "linear",
    });
    return;
  }
  context.actions.push({
    accountId: account.id,
    email,
    googleUserId: google.id,
    provider: "linear",
    type: "suspend",
  });
}

function uniqueProviderEmails(
  provider: ProviderName,
  accounts: DownstreamAccount[],
  diagnostics: AccessDiagnostic[],
): { blocked: boolean; byEmail: Map<string, DownstreamAccount> } {
  const byEmail = new Map<string, DownstreamAccount>();
  let blocked = false;
  for (const account of accounts) {
    const email = normalizeEmail(account.email);
    if (byEmail.has(email)) {
      blocked = true;
      diagnostics.push({
        code: "ambiguous_provider_email",
        context: { email },
        level: "error",
        message:
          "Provider email maps to more than one account; the entire provider is write-blocked",
        provider,
      });
    } else {
      byEmail.set(email, account);
    }
  }
  return { blocked, byEmail };
}

function appendGitHubInvitationDiagnostics(
  invitations: GitHubAccessInvitation[],
  diagnostics: AccessDiagnostic[],
): void {
  for (const invitation of invitations) {
    const target =
      invitation.invitee?.login ?? invitation.email ?? "unassigned";
    diagnostics.push({
      code: "pending_provider_invitation",
      context: {
        "invitation_id": invitation.id,
        role: invitation.role,
        target,
      },
      level: "warning",
      message:
        "Pending GitHub invitation is reported separately and is not active access",
      provider: "github",
    });
  }
}

function processGitHubAccounts(
  accounts: GitHubAccessAccount[],
  context: ProviderProcessingContext,
): void {
  const accountsById = new Map<string, GitHubAccessAccount>();
  const accountsByLogin = new Map<string, GitHubAccessAccount>();
  let blocked = context.googleGitHubIndex.blocked;
  for (const account of accounts) {
    if (accountsById.has(account.id) || accountsByLogin.has(account.login)) {
      blocked = true;
      context.diagnostics.push({
        code: "ambiguous_github_identity",
        context: { "account_id": account.id, "github_login": account.login },
        level: "error",
        message:
          "GitHub returned a duplicate login or stable user ID; reconciliation is blocked",
        provider: "github",
      });
      continue;
    }
    accountsById.set(account.id, account);
    accountsByLogin.set(account.login, account);
  }
  if (blocked) return;
  for (const account of accounts) {
    const idOwner = context.googleGitHubIndex.byUserId.get(account.id);
    const loginOwner = context.googleGitHubIndex.byLogin.get(account.login);
    if (!idOwner && !loginOwner) {
      appendUnmatchedGitHubAccount(account, context);
      continue;
    }
    if (idOwner?.id !== loginOwner?.id) {
      context.diagnostics.push({
        code: "conflicting_github_identity",
        context: { "account_id": account.id, "github_login": account.login },
        level: "error",
        message:
          "GitHub actor login and stable user ID do not resolve to the same Google identity",
        provider: "github",
      });
      continue;
    }
    if (idOwner && isInactiveGoogleUser(idOwner)) {
      appendInactiveGitHubAccount(account, idOwner, context);
    }
  }
}

function appendUnmatchedGitHubAccount(
  account: GitHubAccessAccount,
  context: ProviderProcessingContext,
): void {
  context.issues.push({
    details: { "account_id": account.id, "github_login": account.login },
    id: `u:github:${account.id}`,
    kind: "active_downstream_without_google",
    provider: "github",
    summary: `@${account.login} has GitHub organization access but no Google GitHub identity`,
  });
  context.diagnostics.push({
    code: "unmatched_provider_account",
    context: { "account_id": account.id, "github_login": account.login },
    level: "warning",
    message:
      "Active GitHub actor has no Google identity with the same login and stable user ID",
    provider: "github",
  });
}

function appendInactiveGitHubAccount(
  account: GitHubAccessAccount,
  google: GoogleAccessUser,
  context: ProviderProcessingContext,
): void {
  context.issues.push({
    details: {
      "account_id": account.id,
      email: normalizeEmail(google.primaryEmail),
      "github_login": account.login,
    },
    googleUserId: google.id,
    id: `s:github:${google.id}`,
    kind: "active_downstream_for_inactive_google",
    provider: "github",
    summary: `${normalizeEmail(google.primaryEmail)} is inactive in Google Workspace but @${account.login} retains GitHub organization access`,
  });
}

function enforceSuspensionCap(
  actions: AccessGuardPlan["actions"],
  diagnostics: AccessDiagnostic[],
  maximum: number,
): void {
  if (actions.length <= maximum) return;
  diagnostics.push({
    code: "provider_error",
    context: {
      "action_count": actions.length,
      "error_code": "automatic_suspension_cap_exceeded",
      maximum,
    },
    level: "error",
    message:
      "Linear automatic suspension cap exceeded; every Linear write is blocked",
    provider: "linear",
  });
  actions.length = 0;
}
