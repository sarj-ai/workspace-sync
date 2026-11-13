import { describe, expect, it } from "vitest";

import {
  ReviewedProviderIntentSchema,
  ReviewedSlackLifecycleIntentProofSchema,
} from "../src/execution/reviewed-slack-lifecycle-intent.ts";

const proof = ReviewedSlackLifecycleIntentProofSchema.parse({
  actorHash: "a".repeat(64),
  branchHash: "b".repeat(64),
  leafPlanHash: "c".repeat(64),
  originalPlanHash: "d".repeat(64),
  sourceHash: "e".repeat(64),
  generatedAtMs: 100_000,
  expiresAtMs: 700_000,
  reviewed: {
    googleUserId: "101",
    slackUserId: "UMEMBER",
    slackUserGroupId: "SGROUP",
  },
});
const identity = { intentId: "f".repeat(64), proof };

describe("reviewed provider intent boundary", () => {
  it("accepts an unclaimed approval and a claim inside the original approval lifetime", () => {
    expect(
      ReviewedProviderIntentSchema.parse({
        ...identity,
        state: "pending",
        claimedAtMs: null,
        claimedTickId: null,
      }).state,
    ).toBe("pending");
    expect(
      ReviewedProviderIntentSchema.parse({
        ...identity,
        state: "claimed",
        claimedAtMs: 100_000,
        claimedTickId: "1".repeat(64),
      }).state,
    ).toBe("claimed");
  });

  it.each([
    { state: "pending", claimedAtMs: 100_000, claimedTickId: null },
    { state: "pending", claimedAtMs: null, claimedTickId: "1".repeat(64) },
    { state: "claimed", claimedAtMs: null, claimedTickId: "1".repeat(64) },
    { state: "claimed", claimedAtMs: 100_000, claimedTickId: null },
    { state: "claimed", claimedAtMs: 99_999, claimedTickId: "1".repeat(64) },
    { state: "claimed", claimedAtMs: 700_000, claimedTickId: "1".repeat(64) },
  ])(
    "rejects contradictory ownership and out-of-lifetime claims: %o",
    (invalid) => {
      expect(
        ReviewedProviderIntentSchema.safeParse({ ...identity, ...invalid })
          .success,
      ).toBe(false);
    },
  );
});
