import { describe, expect, it } from "vitest";

import { TrycompSafetyReadModelSchema } from "../src/trycomp/safety.ts";

const boundary = TrycompSafetyReadModelSchema.shape.breaker;
const closed = {
  state: "closed",
  "opened_action_index": null,
  "opened_at_ms": null,
  "opened_run_id": null,
  reason: null,
  "updated_at_ms": 200_000,
};
const review = {
  state: "review_required",
  "opened_action_index": 0,
  "opened_at_ms": 100_000,
  "opened_run_id": "d8f58015-dcf4-435d-8d3b-3cb5b84b39ee",
  reason: "unconfirmed provider effect",
  "updated_at_ms": 200_000,
};

describe("Trycomp breaker state boundary", () => {
  it("accepts a clear breaker and a review-required breaker with opening evidence", () => {
    expect(boundary.parse(closed).state).toBe("closed");
    expect(boundary.parse(review).state).toBe("review_required");
  });

  it.each([
    "opened_action_index",
    "opened_at_ms",
    "opened_run_id",
    "reason",
  ] as const)(
    "rejects stale closed evidence and missing review evidence for %s",
    (field) => {
      expect(
        boundary.safeParse({ ...closed, [field]: review[field] }).success,
      ).toBe(false);
      expect(boundary.safeParse({ ...review, [field]: null }).success).toBe(
        false,
      );
    },
  );
});
