import { resourceLeaseKey } from "../identity-sync/resource-lease.ts";

/** Serializes every Google Group provider mutation owned by Workspace Directory. */
export const GOOGLE_GROUP_MUTATION_RESOURCE_LEASE_KEY = resourceLeaseKey(
  "workspace-directory/google-group-mutations",
);
