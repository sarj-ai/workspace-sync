import type { z } from "zod";

import type { JsonValue } from "../operations/schemas.ts";
import type { DriveOrgChartBranchPlanSchema } from "./contracts.ts";

type ManagedChart = Extract<
  z.output<typeof DriveOrgChartBranchPlanSchema>,
  { execution: "managed" }
>;

/* Legacy hash-only plans remain readable, but cannot authorize the parent attempt path. */
export function assertDriveOrgChartFileId(
  branch: ManagedChart,
  actualFileId: string,
  required: boolean,
): void {
  if (branch.fileId === undefined) {
    if (required)
      throw new Error("workspace_directory_org_chart_file_id_required");
  } else if (branch.fileId !== actualFileId) {
    throw new Error("workspace_directory_org_chart_file_id_changed");
  }
}

export function driveOrgChartManagedSlice(
  branch: ManagedChart,
  sha256: string,
): JsonValue {
  return branch.fileId === undefined
    ? sha256
    : { fileId: branch.fileId, sha256 };
}
