/** Host-owned delivery and deduplication for bounded execution alerts. */
export interface WorkspaceAlertPort {
  postError(
    context: string,
    error: unknown,
    meta?: Record<string, string>,
    dedupTtlSeconds?: number,
    presentation?: {
      tone: "error" | "warning";
      details?: readonly { heading: string; text: string }[];
    },
  ): Promise<unknown>;
}
