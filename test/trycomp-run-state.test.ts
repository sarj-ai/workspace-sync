import { describe, expect, it } from "vitest";

import { TrycompSafetyReadModelSchema } from "../src/trycomp/safety.ts";

const boundary = TrycompSafetyReadModelSchema.shape.latestRuns.element;
const identity = {
  ambiguousCount: 0,
  attemptedCount: 0,
  createdAtMs: 100_000,
  mode: "live",
  planHash: "a".repeat(64),
  plannedCount: 1,
  providerAcceptedCount: 0,
  runId: "d8f58015-dcf4-435d-8d3b-3cb5b84b39ee",
  trigger: "cron",
  verifiedCount: 0,
  workerVersionId: "worker-version",
  workerVersionTag: "b".repeat(40),
  workerVersionTimestamp: "2026-11-12T09:00:00.000Z",
};

describe("Trycomp run lifecycle evidence", () => {
  it.each(["planned", "applying"])(
    "keeps %s unfinished without terminal evidence",
    (state) => {
      expect(
        boundary.parse({
          ...identity,
          state,
          completedAtMs: null,
          errorCode: null,
        }).state,
      ).toBe(state);
      expect(
        boundary.safeParse({
          ...identity,
          state,
          completedAtMs: 200_000,
          errorCode: null,
        }).success,
      ).toBe(false);
      expect(
        boundary.safeParse({
          ...identity,
          state,
          completedAtMs: null,
          errorCode: "stale-error",
        }).success,
      ).toBe(false);
    },
  );

  it("requires a completion receipt without a failure on completed runs", () => {
    expect(
      boundary.parse({
        ...identity,
        state: "completed",
        completedAtMs: 200_000,
        errorCode: null,
      }).state,
    ).toBe("completed");
    expect(
      boundary.safeParse({
        ...identity,
        state: "completed",
        completedAtMs: null,
        errorCode: null,
      }).success,
    ).toBe(false);
    expect(
      boundary.safeParse({
        ...identity,
        state: "completed",
        completedAtMs: 200_000,
        errorCode: "provider-timeout",
      }).success,
    ).toBe(false);
  });

  it.each(["failed", "ambiguous"])(
    "retains the reason and finish time for %s",
    (state) => {
      expect(
        boundary.parse({
          ...identity,
          state,
          completedAtMs: 200_000,
          errorCode: "provider-acknowledgement-unconfirmed",
        }).state,
      ).toBe(state);
      expect(
        boundary.safeParse({
          ...identity,
          state,
          completedAtMs: null,
          errorCode: "provider-acknowledgement-unconfirmed",
        }).success,
      ).toBe(false);
      expect(
        boundary.safeParse({
          ...identity,
          state,
          completedAtMs: 200_000,
          errorCode: null,
        }).success,
      ).toBe(false);
      expect(
        boundary.safeParse({
          ...identity,
          state,
          completedAtMs: 200_000,
          errorCode: "",
        }).success,
      ).toBe(false);
    },
  );
});
