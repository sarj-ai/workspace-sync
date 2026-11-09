import { getWorkspaceSyncPolicy } from "../configuration.ts";

export type { OrgSyncSettings } from "./org-sync-settings-schema.ts";
export { OrgSyncSettingsSchema } from "./org-sync-settings-schema.ts";
export function orgSyncSettings() {
  return getWorkspaceSyncPolicy().org;
}
