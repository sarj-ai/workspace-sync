import { describe, expect, it } from "vitest";

import { contentHash } from "../src/github-access-audit/content-hash.ts";
import { canonicalJson, sha256Hex } from "../src/operations/canonical.ts";
import { JsonValueSchema } from "../src/operations/schemas.ts";

const RUNTIME_VALUE = { value: 0 };
const VALUE = { b: [3, 1, 1], a: { quote: 'é🙂\n"\\', zero: -0 } };
const CANONICAL = String.raw`{"a":{"quote":"é🙂\n\"\\","zero":0},"b":[3,1,1]}`;

describe("serializer compatibility", () => {
  it("retains exact escaped canonical bytes and the existing content digest", async () => {
    const before = structuredClone(VALUE);
    expect(canonicalJson(VALUE)).toBe(CANONICAL);
    await expect(contentHash(VALUE)).resolves.toBe(
      "7a65952cba97161b54b1d21d0164df55a8180b337afb78f4fd47ff224a49bcca",
    );
    expect(VALUE).toEqual(before);
  });

  it("retains different ordered-JSON and multiset-content array semantics", async () => {
    expect(canonicalJson([2, 1, 1])).not.toBe(canonicalJson([1, 1, 2]));
    const unordered = await contentHash([2, 1, 1]);
    await expect(contentHash([1, 1, 2])).resolves.toBe(unordered);
    await expect(contentHash([1, 2])).resolves.not.toBe(unordered);
  });

  it("retains validation and special-key normalization at the JSON boundary", () => {
    const input = JsonValueSchema.parse(
      JSON.parse(
        '{"__proto__":{"safe":true},"constructor":"literal","prototype":7}',
      ),
    );
    expect(canonicalJson(input)).toBe(
      '{"constructor":"literal","prototype":7}',
    );
  });

  it.each([
    { label: "NaN", value: NaN },
    { label: "infinity", value: Infinity },
    { label: "undefined", value: undefined },
    { label: "BigInt", value: 1n },
    { label: "symbol", value: Symbol("invalid") },
    { label: "function", value: () => undefined },
  ])(
    "rejects a malformed runtime $label before canonical serialization",
    async ({ value }) => {
      const input = structuredClone(RUNTIME_VALUE);
      Object.assign(input, { value });
      expect(() => canonicalJson(input)).toThrow();
      await expect(sha256Hex(input)).rejects.toThrow();
    },
  );

  it("retains unknown-content fallback behavior", async () => {
    await expect(contentHash(new Date("2026-01-01T00:00:00Z"))).resolves.toBe(
      "1c70cc7d7f55673a946a6168737b6442dffc8c575a27767dbeafa4a30b8837ab",
    );
    await expect(contentHash(undefined)).resolves.toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    await expect(contentHash(1n)).rejects.toThrow(TypeError);
  });
});
