import { sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";

interface BranchReceipt {
  change: { changeKey: string; text: string };
  handle: {
    announcementDigest: string;
    changeKey: string;
    channelId: string;
    timestamp: string;
  };
}

/* Binds the exact ordered immutable receipt set without depending on mutable ledger state. */
export function orderedBranchReceiptSetDigest(
  receipts: readonly BranchReceipt[],
): Promise<string> {
  return sha256Hex(
    JsonValueSchema.parse(
      receipts.map(({ change, handle }) => ({
        announcementDigest: handle.announcementDigest,
        change,
        changeKey: handle.changeKey,
        channelId: handle.channelId,
        timestamp: handle.timestamp,
      })),
    ),
  );
}
