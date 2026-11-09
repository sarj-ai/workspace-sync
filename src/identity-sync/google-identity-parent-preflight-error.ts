/** A rejected preflight is not an ambiguous provider write and cannot be recovered as success. */
export class GoogleIdentityParentPreflightError extends Error {
  constructor(options: { cause: unknown }) {
    super("google_identity_parent_preflight_failed", options);
    this.name = "GoogleIdentityParentPreflightError";
  }
}
