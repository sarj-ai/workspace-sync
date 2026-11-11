/** Provider writes are available only to the durable parent workflow. */
export type WorkspaceProviderExecution =
  | { readonly kind: "audit" }
  | { readonly kind: "parent" };
