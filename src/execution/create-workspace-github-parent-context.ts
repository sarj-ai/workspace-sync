import type { GitHubOrganizationWriteContext } from "../identity-provisioning/github-organization-connector.ts";
import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import { sameJson } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import {
  createWorkspaceIdentityParentContext,
  type WorkspaceIdentityParentInput,
} from "./create-workspace-identity-parent-context.ts";

type Input = Omit<WorkspaceIdentityParentInput, "identityBudget"> & {
  githubIdentityBudget?: IdentityWriteBudget;
};

export function createWorkspaceGithubParentContext(
  input: Input,
): (plan: WorkspaceDirectoryPlan) => GitHubOrganizationWriteContext {
  return (plan) => {
    const branch = input.params.plan.branches[3];
    if (branch.execution !== "managed" || branch.selectedOperation === null)
      throw new Error("workspace_github_signed_target_required");
    const reviewed = branch.selectedOperation.operation;
    const parent = createWorkspaceIdentityParentContext(
      {
        ...input,
        ...(!(input.githubIdentityBudget === undefined) && {
          identityBudget: input.githubIdentityBudget,
        }),
        now: () => input.now?.() ?? Date.now(),
      },
      plan,
      "github-access",
    );
    return {
      assertFreshPlan: () => parent.assertFreshPlan(),
      assertWriteAuthority: async (actual) => {
        if (
          !sameJson(
            JsonValueSchema.parse(actual),
            JsonValueSchema.parse(reviewed),
          )
        )
          throw new Error("workspace_github_signed_target_mismatch");
        await parent.assertWriteAuthority();
      },
    };
  };
}
