import { sha256 } from "../runtime/sha256.ts";
import type { AuthoritativeGoogleDirectoryUserState } from "./contracts.ts";

// Preserve the event ledger's original byte representation for existing payload hashes.
export async function authorityPayloadHash(
  state: AuthoritativeGoogleDirectoryUserState,
): Promise<string> {
  return sha256(JSON.stringify(state));
}
