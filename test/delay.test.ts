import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { defaultSleep as delay } from "../src/org-sync/http.ts";

describe("retry delay", () => {
  it("keeps a Node process alive until an awaited retry delay finishes", async () => {
    const source = new URL("../src/org-sync/http.ts", import.meta.url).href;
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { defaultSleep as delay } from ${JSON.stringify(source)}; await delay(10); process.stdout.write('finished');`,
      ],
      { timeout: 5000 },
    );
    expect(stdout).toBe("finished");
  });

  it("cancels an awaited delay without retaining its timer or leaking the abort reason", async () => {
    const controller = new AbortController();
    const waiting = delay(30_000, controller.signal);
    controller.abort(new Error("private-caller-reason"));
    await expect(waiting).rejects.toThrow("HTTP retry delay cancelled");
    await expect(waiting).rejects.not.toHaveProperty("cause");
  });

  it.each([-1, 1.5, NaN, Infinity, 2_147_483_648])(
    "rejects invalid timer delay %s",
    async (value) => {
      await expect(delay(value)).rejects.toThrow(RangeError);
    },
  );
});
