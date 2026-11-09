import { describe, expect, it, vi } from "vitest";

import { slackRetryAfterMs } from "../src/org-sync/slack-rate-limit.ts";

function rateLimited(retryAfter?: string): Response {
  return new Response(null, {
    headers: retryAfter === undefined ? {} : { "retry-after": retryAfter },
    status: 429,
  });
}

describe("slackRetryAfterMs", () => {
  it("supports Slack seconds and HTTP-date Retry-After values without truncation", () => {
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-04T00:00:00Z"));

    expect(slackRetryAfterMs(rateLimited("61"))).toBe(61_000);
    expect(
      slackRetryAfterMs(rateLimited("Thu, 04 Sep 2026 00:02:00 GMT")),
    ).toBe(120_000);
  });

  it.each([undefined, "", "invalid", "9".repeat(400)])(
    "uses the bounded default for a missing or malformed header (%s)",
    (value) => {
      expect(slackRetryAfterMs(rateLimited(value))).toBe(1_000);
    },
  );
});
