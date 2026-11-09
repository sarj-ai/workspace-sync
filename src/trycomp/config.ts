import { resourceLeaseKey } from "../identity-sync/resource-lease.ts";

export const TRYCOMP_SYNC_RESOURCE_LEASE_KEY = resourceLeaseKey(
  "org-sync/trycomp-people",
);
export const TRYCOMP_SYNC_RESOURCE_LEASE_DURATION_MS = 5 * 60_000;
export const TRYCOMP_SYNC_MINIMUM_LEASE_HEADROOM_MS = 45_000;
export const TRYCOMP_SCHEDULE_ATTEMPT_ABANDONED_AFTER_MS = 10 * 60_000;
export const TRYCOMP_SCHEDULE_MAX_AGE_MS = 2 * 60 * 60_000 + 15 * 60_000;
