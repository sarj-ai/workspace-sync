import {
  type EmployeeEntitlementAuthority,
  hasCompleteEmployeeEntitlementAuthority,
} from "../identity-provisioning/employee-entitlement-policy.ts";
import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { googleAuthorityFingerprintRecord } from "../org-sync/google-directory-authority.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";

/* Provider state and candidate ordering cannot change this source-only fingerprint. */
export async function fingerprintNameAuthority(
  users: readonly GoogleDirectoryUser[],
  contractorAuthority?: EmployeeEntitlementAuthority,
): Promise<string> {
  if (
    contractorAuthority !== undefined &&
    !hasCompleteEmployeeEntitlementAuthority(contractorAuthority)
  )
    throw new Error("name_authority_contractor_evidence_incomplete");
  return sha256Hex(
    JsonValueSchema.parse({
      googleUsers: users
        .map((user) => ({
          ...googleAuthorityFingerprintRecord(user),
          fullName: user.name?.fullName?.trim() ?? null,
        }))
        .toSorted((left, right) => left.id.localeCompare(right.id)),
      ...(!(contractorAuthority === undefined) && {
        contractorAuthority: contractorAuthority.fingerprint,
      }),
    }),
  );
}
