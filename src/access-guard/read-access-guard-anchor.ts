import {
  type AccessGuardAnchor,
  type accessGuardSlackMetadata,
  parseAccessGuardSlackMetadata,
} from "./issue-set.ts";

export type SlackAnchorLookup =
  | { kind: "found"; metadata: unknown }
  | { kind: "missing" };

export interface AccessGuardSlackAnchorStore {
  findUniqueAnchor(options: {
    includeAllMetadata: true;
    pagination: "all";
    runId: string;
  }): Promise<SlackAnchorLookup>;
  upsertUniqueAnchor(input: {
    metadata: ReturnType<typeof accessGuardSlackMetadata>;
    runId: string;
  }): Promise<void>;
}

export async function readAccessGuardAnchor(
  store: AccessGuardSlackAnchorStore,
  runId: string,
): Promise<AccessGuardAnchor | null> {
  const lookup = await store.findUniqueAnchor({
    includeAllMetadata: true,
    pagination: "all",
    runId,
  });
  if (lookup.kind === "missing") return null;
  const parsed = parseAccessGuardSlackMetadata(lookup.metadata);
  if (!parsed) throw new Error("access_guard_anchor_metadata_invalid");
  return parsed;
}
