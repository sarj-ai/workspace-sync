import { z } from "zod";

import type { AccessGuardPlan, AccessIssue } from "./model.ts";

interface ReconcileIssueSetResult {
  anchor: AccessGuardAnchor;
  newIssues: AccessIssue[];
  resolvedIssueIds: string[];
}

export const ACCESS_GUARD_MIN_INTERVAL_MS = 48 * 60 * 60 * 1_000;
export const ACCESS_GUARD_INCOMPLETE_RETRY_MS = 55 * 60 * 1_000;

export const AccessGuardAnchorSchema = z.object({
  issueIds: z.array(z.string().min(1)).default([]),
  lastAttemptAt: z.iso.datetime(),
  lastSuccessAt: z.iso.datetime().nullable(),
  version: z.literal(1),
});
export type AccessGuardAnchor = z.output<typeof AccessGuardAnchorSchema>;

export function shouldRunAccessGuard(
  now: Date,
  previous: AccessGuardAnchor | null,
): boolean {
  if (!previous) return true;
  const lastAttempt = Date.parse(previous.lastAttemptAt);
  if (!Number.isFinite(lastAttempt) || lastAttempt > now.getTime()) return true;
  const lastSuccess = previous.lastSuccessAt
    ? Date.parse(previous.lastSuccessAt)
    : NaN;
  const previousAttemptCompleted =
    Number.isFinite(lastSuccess) && lastSuccess >= lastAttempt;
  const interval = previousAttemptCompleted
    ? ACCESS_GUARD_MIN_INTERVAL_MS
    : ACCESS_GUARD_INCOMPLETE_RETRY_MS;
  return now.getTime() - lastAttempt >= interval;
}

export function canAdvanceAccessGuardAnchor(plan: AccessGuardPlan): boolean {
  return plan.diagnostics.every((diagnostic) => diagnostic.level !== "error");
}

export function canApplyLinearPlan(plan: AccessGuardPlan): boolean {
  return plan.diagnostics.every(
    (diagnostic) =>
      diagnostic.level !== "error" ||
      (diagnostic.provider !== undefined && diagnostic.provider !== "linear"),
  );
}

export function reconcileIssueSet(
  previous: AccessGuardAnchor | null,
  issues: AccessIssue[],
  completedAt: Date,
  outcome: "complete" | "incomplete",
): ReconcileIssueSetResult {
  const previousIds = previous ? new Set(previous.issueIds) : new Set<string>();
  const currentById = new Map(issues.map((issue) => [issue.id, issue]));
  const currentIds = currentById.keys().toArray().toSorted();
  const anchorIssueIds =
    outcome === "complete"
      ? currentIds
      : previousIds
          .union(new Set(currentIds))
          .values()
          .toArray()
          .toSorted((left, right) => left.localeCompare(right));
  return {
    anchor: AccessGuardAnchorSchema.parse({
      issueIds: anchorIssueIds,
      lastAttemptAt: completedAt.toISOString(),
      lastSuccessAt:
        outcome === "complete"
          ? completedAt.toISOString()
          : (previous?.lastSuccessAt ?? null),
      version: 1,
    }),
    newIssues: currentIds.flatMap((id) => {
      const issue = currentById.get(id);
      return issue && !previousIds.has(id) ? [issue] : [];
    }),
    resolvedIssueIds:
      outcome === "complete"
        ? previousIds
            .values()
            .filter((id) => !currentById.has(id))
            .toArray()
            .toSorted((left, right) => left.localeCompare(right))
        : [],
  };
}

export const AccessGuardSlackMetadataSchema = z.object({
  "event_payload": z.object({ anchor: AccessGuardAnchorSchema }),
  "event_type": z.literal("sarj_access_guard_state"),
});
export type AccessGuardSlackMetadata = z.output<
  typeof AccessGuardSlackMetadataSchema
>;

export function accessGuardSlackMetadata(
  anchor: AccessGuardAnchor,
): AccessGuardSlackMetadata {
  return AccessGuardSlackMetadataSchema.parse({
    "event_payload": { anchor },
    "event_type": "sarj_access_guard_state",
  });
}

export function parseAccessGuardSlackMetadata(
  value: unknown,
): AccessGuardAnchor | null {
  const parsed = AccessGuardSlackMetadataSchema.safeParse(value);
  return parsed.success ? parsed.data["event_payload"].anchor : null;
}
