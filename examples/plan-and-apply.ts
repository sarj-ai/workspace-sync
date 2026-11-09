import type { IdentityWriteBudget } from "../src/identity-provisioning/identity-budget-contracts.ts";
import type {
  OrgSyncRunReport,
  OrgSyncServiceContract,
} from "../src/org-sync/service.ts";

export function plan(sync: OrgSyncServiceContract): Promise<OrgSyncRunReport> {
  return sync.run({ mode: "audit", trigger: "local" });
}

export function apply(
  sync: OrgSyncServiceContract,
  reviewed: Pick<OrgSyncRunReport, "planHash">,
  identityBudget: IdentityWriteBudget,
): Promise<OrgSyncRunReport> {
  return sync.run({
    mode: "live",
    trigger: "local",
    expectedPlanHash: reviewed.planHash,
    identityBudget,
  });
}
