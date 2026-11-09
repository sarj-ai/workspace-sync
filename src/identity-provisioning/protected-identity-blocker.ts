import { orgSyncSettings } from "../org-sync/config.ts";

/* Deny independently of downstream roles and mutable contractor/team mappings. */
export function protectedIdentityBlocker(subject: {
  readonly aliases?: readonly string[] | undefined;
  readonly googleUserId: string;
  readonly isAdmin?: boolean | undefined;
  readonly isDelegatedAdmin?: boolean | undefined;
  readonly primaryEmail: string;
}): string | undefined {
  const emails = [subject.primaryEmail, ...(subject.aliases ?? [])].map(
    (email) => email.trim().toLowerCase(),
  );
  if (
    orgSyncSettings().expectedRootGoogleUserIds.includes(
      subject.googleUserId,
    ) ||
    emails.includes(orgSyncSettings().googleAdminSubject.toLowerCase()) ||
    subject.isAdmin === true ||
    subject.isDelegatedAdmin === true
  ) {
    return "Protected Google identity cannot be changed by automatic provider reconciliation";
  }
  if (subject.isAdmin !== false || subject.isDelegatedAdmin !== false) {
    return "Complete Google administrator authority is required before provider mutation";
  }
  return undefined;
}
