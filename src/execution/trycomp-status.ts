import { z } from "zod";

import {
  type TrycompSafetyReadModel,
  TrycompSafetyReadModelSchema,
} from "../trycomp/safety.ts";
import { WorkspaceScheduleHealthSchema } from "./schedule-health-contracts.ts";
import type { WorkspaceScheduleHealth } from "./workspace-schedule-health-repository.ts";

export interface ParentTrycompStatus {
  legacy: TrycompSafetyReadModel;
  parent: WorkspaceScheduleHealth;
  scheduleSource: "workspace-directory";
  selectedScheduleHealthy: boolean;
}
export type TrycompStatusResponse =
  | TrycompSafetyReadModel
  | ParentTrycompStatus;
export const ParentTrycompStatusSchema: z.ZodType<ParentTrycompStatus> =
  z.strictObject({
    legacy: TrycompSafetyReadModelSchema,
    parent: WorkspaceScheduleHealthSchema,
    scheduleSource: z.literal("workspace-directory"),
    selectedScheduleHealthy: z.boolean(),
  });

// Flag-off clients retain exactly the legacy payload; parent mode is explicit.
export const TrycompStatusResponseSchema: z.ZodType<TrycompStatusResponse> =
  z.union([TrycompSafetyReadModelSchema, ParentTrycompStatusSchema]);

export function parentTrycompStatus(
  legacyRaw: TrycompSafetyReadModel,
  parentRaw: WorkspaceScheduleHealth,
): ParentTrycompStatus {
  const legacy = TrycompSafetyReadModelSchema.parse(legacyRaw);
  const parent = WorkspaceScheduleHealthSchema.parse(parentRaw);
  const legacyEvidenceClear =
    legacy.breaker.state === "closed" &&
    !legacy.effectiveBreaker &&
    legacy.unresolvedMutations === 0 &&
    legacy.notificationHealth.acceptedCount === 0 &&
    legacy.notificationHealth.pendingCount === 0 &&
    legacy.notificationHealth.healthy &&
    legacy.notificationHealth.claimedCount === 0 &&
    legacy.notificationHealth.missingEvidenceCount === 0 &&
    legacy.scheduleHealth.missingNotificationEvidenceCount === 0 &&
    legacy.scheduleHealth.staleAttemptCount === 0;
  return ParentTrycompStatusSchema.parse({
    legacy,
    parent,
    scheduleSource: "workspace-directory",
    selectedScheduleHealthy: parent.healthy && legacyEvidenceClear,
  });
}
