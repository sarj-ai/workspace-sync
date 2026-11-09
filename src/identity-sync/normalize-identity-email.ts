/* Canonical key for identity joins across systems of record and downstream providers. */
export function normalizeIdentityEmail(value: string): string {
  return value.trim().toLocaleLowerCase("en-US");
}
