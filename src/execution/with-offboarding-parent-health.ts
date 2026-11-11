import { z } from "zod";

import type { OffboardingStatus } from "./offboarding-status.ts";
import type { WorkspaceRuntimeConfiguration as ValidatedEnv } from "./runtime-configuration.ts";
const ParentHealthSchema = z.object({
  mutationSafetyClear: z.boolean(),
  scheduleHealthy: z.boolean(),
  unresolvedMutations: z.number().int().nonnegative(),
});
type ProviderStatus = OffboardingStatus["providers"][number];
type ParentOwnership = Pick<
  ValidatedEnv,
  "workspaceDirectoryParentEnabled" | "workspaceDirectoryTrycompEnabled"
>;
export async function withOffboardingParentHealth(
  report: OffboardingStatus,
  env: ParentOwnership,
  readHealth: () => Promise<unknown>,
): Promise<OffboardingStatus> {
  const needsHealth = (provider: ProviderStatus) =>
    provider.accountState === "active" &&
    provider.capability === "automatic" &&
    provider.blocker === "deactivation_pending" &&
    env.workspaceDirectoryParentEnabled &&
    (provider.provider === "linear" ||
      provider.provider === "sentry" ||
      (provider.provider === "trycomp" &&
        env.workspaceDirectoryTrycompEnabled));
  if (!report.providers.some(needsHealth)) return report;
  let blocker: ProviderStatus["blocker"];
  try {
    const health = ParentHealthSchema.parse(await readHealth());
    if (!health.mutationSafetyClear || health.unresolvedMutations > 0) {
      blocker = "parent_mutation_safety_unresolved";
    } else {
      blocker = health.scheduleHealthy
        ? "deactivation_pending"
        : "parent_schedule_unhealthy";
    }
  } catch {
    blocker = "parent_schedule_health_unavailable";
  }
  return {
    ...report,
    providers: report.providers.map((provider) =>
      needsHealth(provider) ? { ...provider, blocker } : provider,
    ),
  };
}
