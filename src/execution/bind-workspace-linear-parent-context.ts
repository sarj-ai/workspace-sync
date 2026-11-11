import type {
  LinearSuspensionParentContext,
  LinearSuspensionWriteContext,
} from "../access-guard/provider.ts";

/* Google authority is refreshed after durable parent reads, at the provider dispatch boundary. */
export function bindWorkspaceLinearParentContext(
  parent: LinearSuspensionParentContext | undefined,
  assertGoogleAuthority: () => Promise<unknown>,
): LinearSuspensionWriteContext | undefined {
  if (parent === undefined) return undefined;
  return {
    assertFinalSourceAuthority: async () => {
      await assertGoogleAuthority();
      parent.assertFreshPlan();
    },
    assertFreshPlan: () => parent.assertFreshPlan(),
    assertWriteAuthority: async (action) => {
      await parent.assertWriteAuthority(action);
      await assertGoogleAuthority();
      parent.assertFreshPlan();
    },
  };
}
