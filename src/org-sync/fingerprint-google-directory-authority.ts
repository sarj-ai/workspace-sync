import { sha256Hex } from "../operations/canonical.ts";
import { googleAuthorityFingerprintRecord } from "./google-directory-authority.ts";
import type { GoogleDirectoryUser } from "./model.ts";

export async function fingerprintGoogleDirectoryAuthority(
  users: readonly GoogleDirectoryUser[],
): Promise<string> {
  return sha256Hex(
    users
      .map(googleAuthorityFingerprintRecord)
      .toSorted((left, right) => left.id.localeCompare(right.id)),
  );
}
