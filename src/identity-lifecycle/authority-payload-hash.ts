import type { AuthoritativeGoogleDirectoryUserState } from "./contracts.ts";

// Preserve the event ledger's original byte representation for existing payload hashes.
export async function authorityPayloadHash(
  state: AuthoritativeGoogleDirectoryUserState,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(state)),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
