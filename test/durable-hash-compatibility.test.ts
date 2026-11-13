import { describe, expect, it } from "vitest";

import { orderedBranchReceiptSetDigest } from "../src/execution/ordered-branch-receipt-set-digest.ts";
import { stableSlackClientMessageId } from "../src/shared/stable-slack-client-message-id.ts";

function receipt(index: number) {
  return {
    change: {
      changeKey: `change/${String(index)}`,
      text: `full é🙂 title ${String(index)}`,
    },
    handle: {
      announcementDigest: "a".repeat(64),
      changeKey: `handle/${String(index)}`,
      channelId: `channel/${String(index % 3)}`,
      timestamp: `1234567.${String(index)}`,
    },
  };
}
const SINGLE_DIGEST =
  "6bb8cc8a5e031838ecfb33fcbaa5f2c6384f7b3c1d86ad8d83a8154b774e8449";

describe("durable receipt hashes", () => {
  it.each([
    [0, "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"],
    [1, SINGLE_DIGEST],
    [6, "fbaa38f67b3053e527dfaf1c169931298b836c464aabefeb485698d1d9ea33dd"],
  ] as const)(
    "preserves the existing digest for %i receipts",
    async (size, digest) => {
      await expect(
        orderedBranchReceiptSetDigest(
          Array.from({ length: size }, (_, index) => receipt(index)),
        ),
      ).resolves.toBe(digest);
    },
  );

  it.each([
    "announcementDigest",
    "changeKey",
    "channelId",
    "timestamp",
  ] as const)("binds the full handle %s", async (field) => {
    const input = receipt(0);
    input.handle[field] += ".changed";
    await expect(orderedBranchReceiptSetDigest([input])).resolves.not.toBe(
      SINGLE_DIGEST,
    );
  });

  it.each(["changeKey", "text"] as const)(
    "binds the full change %s",
    async (field) => {
      const input = receipt(0);
      input.change[field] += ".changed";
      await expect(orderedBranchReceiptSetDigest([input])).resolves.not.toBe(
        SINGLE_DIGEST,
      );
    },
  );

  it("preserves ordering, duplicate receipts and input objects", async () => {
    const input = [receipt(0), receipt(1)];
    const snapshot = structuredClone(input);
    const digest = await orderedBranchReceiptSetDigest(input);
    await expect(
      orderedBranchReceiptSetDigest(input.toReversed()),
    ).resolves.not.toBe(digest);
    await expect(
      orderedBranchReceiptSetDigest([receipt(0), receipt(0)]),
    ).resolves.not.toBe(SINGLE_DIGEST);
    expect(input).toEqual(snapshot);
  });

  it("retains synchronous validation failure for malformed persisted fields", () => {
    const input = receipt(0);
    Object.assign(input.handle, { timestamp: undefined });
    expect(() => orderedBranchReceiptSetDigest([input])).toThrow();
  });
});

describe("stable Slack client message IDs", () => {
  it.each([
    ["receipt/day-1/branch:0.delivery", "c260a45a-02ca-515a-b513-8acc0a35f19d"],
    ["empty/day:0", "c406acce-4f1d-5d45-b1e7-9e5f5abbbfb0"],
    ["a", "ca978112-ca1b-5dca-bac2-31b39a23dc4d"],
  ])("preserves the existing ID for %s", async (key, id) => {
    await expect(stableSlackClientMessageId(key)).resolves.toBe(id);
  });

  it.each(["", "UPPER", "a//b", "a@b", "a_b", ".", "a\n"])(
    "rejects an invalid delivery key %j",
    async (key) => {
      await expect(stableSlackClientMessageId(key)).rejects.toMatchObject({
        name: "ZodError",
      });
    },
  );
});
