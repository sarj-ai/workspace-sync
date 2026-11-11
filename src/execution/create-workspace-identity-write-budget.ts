import type { D1Database } from "@cloudflare/workers-types";

import type {
  IdentityBudgetParentKey,
  IdentityBudgetServiceId,
  IdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { IdentityBudgetRepository } from "../identity-provisioning/identity-budget-repository.ts";

export function createWorkspaceIdentityWriteBudget(
  database: D1Database,
  parentExecutionKey: IdentityBudgetParentKey,
  serviceId: IdentityBudgetServiceId,
): IdentityWriteBudget {
  const repository = new IdentityBudgetRepository(database);
  return {
    required: true,
    reserve: async (googleUserId) => {
      await repository.reserve({
        parentExecutionKey,
        serviceId,
        googleUserIds: [googleUserId],
      });
    },
  };
}
