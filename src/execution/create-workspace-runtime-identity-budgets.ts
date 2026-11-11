import type { D1Database } from "@cloudflare/workers-types";

import type { IdentityBudgetParentKey } from "../identity-provisioning/identity-budget-contracts.ts";
import { createWorkspaceIdentityWriteBudget } from "./create-workspace-identity-write-budget.ts";

export function createWorkspaceRuntimeIdentityBudgets(
  database: D1Database,
  parentExecutionKey?: IdentityBudgetParentKey,
) {
  if (parentExecutionKey === undefined) return {};
  return {
    pagerDutyIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "pagerduty",
    ),
    sentryIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "sentry",
    ),
    githubIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "github",
    ),
    googleIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "google-workspace",
    ),
    linearIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "linear",
    ),
    slackIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "slack",
    ),
    trycompIdentityBudget: createWorkspaceIdentityWriteBudget(
      database,
      parentExecutionKey,
      "trycomp",
    ),
  };
}
