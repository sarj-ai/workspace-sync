import { describe, expect, it } from "vitest";

import {
  chunk,
  forEachSequential,
  mapSequential,
  reduceSequential,
} from "../src/runtime/sequential.ts";

describe("runtime sequential helpers", () => {
  it("captures the source values before deferring the first visit", async () => {
    const source = ["first", "second"];
    const visited: string[] = [];
    const pending = forEachSequential(source, async (value) => {
      visited.push(value);
    });

    expect(visited).toEqual([]);
    source[0] = "replacement";
    source.push("later");
    await pending;

    expect(visited).toEqual(["first", "second"]);
  });

  it("waits for each visit before starting the next one", async () => {
    const events: string[] = [];

    await forEachSequential(["first", "second"], async (value) => {
      events.push(`${value}:start`);
      await Promise.resolve();
      events.push(`${value}:finish`);
    });

    expect(events).toEqual([
      "first:start",
      "first:finish",
      "second:start",
      "second:finish",
    ]);
  });

  it("stops after the first rejected visit", async () => {
    const visited: string[] = [];

    await expect(
      forEachSequential(["first", "second", "third"], async (value) => {
        visited.push(value);
        if (value === "second") throw new Error("stop");
      }),
    ).rejects.toThrow("stop");
    expect(visited).toEqual(["first", "second"]);
  });

  it("chunks without mutating the source collection", () => {
    const source = [1, 2, 3, 4, 5];

    expect(chunk(source, 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(source).toEqual([1, 2, 3, 4, 5]);
    expect(() => chunk(source, 0)).toThrow("Chunk size must be positive");
  });

  it("maps values without overlapping work", async () => {
    let active = 0;
    let peakActive = 0;

    const results = await mapSequential([2, 3, 4], async (value) => {
      active += 1;
      peakActive = Math.max(peakActive, active);
      await Promise.resolve();
      active -= 1;
      return value * 2;
    });

    expect(results).toEqual([4, 6, 8]);
    expect(peakActive).toBe(1);
  });

  it("passes each accumulated result to the next reduction step", async () => {
    const result = await reduceSequential(
      [2, 3, 4],
      1,
      async (total, value) => total * value,
    );

    expect(result).toBe(24);
  });

  it("captures reduction inputs before deferring the first step", async () => {
    const source = [2, 3];
    const visited: number[] = [];
    const pending = reduceSequential(source, 1, async (total, value) => {
      visited.push(value);
      return total * value;
    });

    expect(visited).toEqual([]);
    source[0] = 10;
    source.push(4);

    await expect(pending).resolves.toBe(6);
    expect(visited).toEqual([2, 3]);
  });

  it("stops reduction after a rejected step", async () => {
    const visited: number[] = [];
    const failure = new Error("stop reduction");

    await expect(
      reduceSequential([2, 3, 4], 1, async (total, value) => {
        visited.push(value);
        if (value === 3) throw failure;
        return total * value;
      }),
    ).rejects.toBe(failure);
    expect(visited).toEqual([2, 3]);
  });
});
