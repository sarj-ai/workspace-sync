import { SlackProfileSync } from "../src/configuration.ts";
import type {
  OrgSyncRunReport,
  OrgSyncServiceOptions,
} from "../src/org-sync/service.ts";

export async function syncProfiles(
  options: OrgSyncServiceOptions,
  approve: (plan: OrgSyncRunReport) => Promise<boolean>,
): Promise<OrgSyncRunReport> {
  const sync = new SlackProfileSync(options);
  const plan = await sync.plan();
  if (await approve(plan)) return sync.apply(plan);
  return plan;
}
