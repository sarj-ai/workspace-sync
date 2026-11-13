import { z } from "zod";

import { GoogleUserIdSchema } from "../catalog/identity-authority.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import { fingerprintGoogleDirectoryAuthority } from "../org-sync/fingerprint-google-directory-authority.ts";
import {
  type GoogleDirectoryUser,
  isActiveGoogleDirectoryUser,
} from "../org-sync/model.ts";
import { normalizeIdentityEmail } from "./normalize-identity-email.ts";

const TargetEvidenceSchema = z.object({
  aliases: z.array(z.string()).optional(),
  archived: z.boolean().optional(),
  deletionTime: z.string().optional(),
  id: GoogleUserIdSchema,
  isAdmin: z.literal(false),
  isDelegatedAdmin: z.literal(false),
  nonEditableAliases: z.array(z.string()).optional(),
  primaryEmail: z.email(),
  suspended: z.boolean().optional(),
});

export async function assertGoogleIdentityParentAuthority(input: {
  expectedBeforeFingerprint: string;
  googleUserId: string;
  users: readonly GoogleDirectoryUser[];
  wire: unknown;
}): Promise<void> {
  const id = GoogleUserIdSchema.parse(input.googleUserId);
  const ids = input.users.map((user) => GoogleUserIdSchema.parse(user.id));
  const target = input.users.find((user) => user.id === id);
  const wire = TargetEvidenceSchema.parse(input.wire);
  if (
    new Set(ids).size !== ids.length ||
    target === undefined ||
    wire.id !== id
  )
    throw new Error("google_identity_parent_target_mismatch");
  const evidence = TargetEvidenceSchema.parse(target);
  if (!sameJson(JsonValueSchema.parse(wire), JsonValueSchema.parse(evidence)))
    throw new Error("google_identity_parent_target_evidence_drift");
  const aliases = [
    ...(target.aliases ?? []),
    ...(target.nonEditableAliases ?? []),
  ];
  const emails = new Set(
    [target.primaryEmail, ...aliases].map(normalizeIdentityEmail),
  );
  if (
    !isActiveGoogleDirectoryUser(target) ||
    orgSyncSettings().protectedDepartedGoogleUserIds.includes(id) ||
    protectedIdentityBlocker({ ...target, aliases, googleUserId: id }) !==
      undefined ||
    input.users.some(
      (user) =>
        user.id !== id &&
        [
          user.primaryEmail,
          ...(user.aliases ?? []),
          ...(user.nonEditableAliases ?? []),
        ].some((email) => emails.has(normalizeIdentityEmail(email))),
    )
  )
    throw new Error("google_identity_parent_target_ineligible");
  const fingerprint = await fingerprintGoogleDirectoryAuthority(input.users);
  if (fingerprint !== input.expectedBeforeFingerprint)
    throw new Error("google_identity_parent_authority_drift");
}
