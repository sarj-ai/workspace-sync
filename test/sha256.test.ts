import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { contentHash } from "../src/github-access-audit/content-hash.ts";
import { googleWatchTokenSha256 } from "../src/identity-lifecycle/channel-authenticator.ts";
import {
  bytesToHex,
  canonicalJson,
  sha256Hex,
} from "../src/operations/canonical.ts";
import { sha256 } from "../src/runtime/sha256.ts";

const expected = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

describe("shared SHA-256", () => {
  it("preserves canonical keys and JSON scalar encoding", () => {
    expect(
      canonicalJson({
        z: 'line\n"quoted"',
        a: [null, false, true, -0, 1.25, ""],
      }),
    ).toBe(
      String.raw`{"a":[null,false,true,0,1.25,""],"z":"line\n\"quoted\""}`,
    );
  });

  it.each([NaN, -Infinity, Infinity])(
    "rejects nonfinite JSON values: %s",
    (value) => {
      expect(() => canonicalJson(value)).toThrow();
      expect(() => canonicalJson({ nested: [value] })).toThrow();
    },
  );

  it.each(["", "abc", "人员 → profile 🔐", "first\nsecond"])(
    "preserves UTF-8 bytes: %j",
    async (value) => {
      await expect(sha256(value)).resolves.toBe(expected(value));
      await expect(googleWatchTokenSha256(value)).resolves.toBe(
        expected(value),
      );
    },
  );

  it("keeps the existing ordered and unordered JSON hash contracts distinct", async () => {
    const first = { z: 1, a: ["first", "second"] };
    const reversed = { a: ["second", "first"], z: 1 };
    await expect(sha256Hex(first)).resolves.toBe(
      expected(canonicalJson(first)),
    );
    await expect(sha256Hex(reversed)).resolves.not.toBe(await sha256Hex(first));
    await expect(contentHash(reversed)).resolves.toBe(await contentHash(first));
  });

  it("preserves the public hexadecimal encoding helper", () => {
    expect(bytesToHex(new Uint8Array([0, 1, 15, 16, 255]))).toBe("00010f10ff");
  });
});
