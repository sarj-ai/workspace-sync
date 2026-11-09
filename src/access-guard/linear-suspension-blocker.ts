import { orgSyncSettings } from "../org-sync/config.ts";
import type { DownstreamAccount } from "./model.ts";

export function linearSuspensionBlocker(
  account: DownstreamAccount,
  googleUserId?: string,
  identityEmails: readonly string[] = [],
): string | undefined {
  if (
    [account.email, ...identityEmails].some(
      (email) =>
        email.trim().toLowerCase() ===
        orgSyncSettings().googleAdminSubject.toLowerCase(),
    ) ||
    (googleUserId !== undefined &&
      orgSyncSettings().expectedRootGoogleUserIds.includes(googleUserId))
  ) {
    return "linear_protected_identity";
  }
  if (
    account.admin === true ||
    account.owner === true ||
    account.app === true
  ) {
    return "linear_privileged_or_app_account";
  }
  if (
    account.admin !== false ||
    account.owner !== false ||
    account.app !== false
  ) {
    return "linear_role_authority_incomplete";
  }
  return undefined;
}
