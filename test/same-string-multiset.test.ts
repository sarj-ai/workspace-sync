import { expect, it } from "vitest";

import { sameStringMultiset } from "../src/shared/same-string-multiset.ts";

it.each([
  [[], [], true],
  [["a"], [], false],
  [["a", "b"], ["b", "a"], true],
  [["a", "a"], ["a", "b"], false],
  [["a", "a", "b"], ["b", "a", "a"], true],
  [["a", "a"], ["a"], false],
  [["", "😀", "ä", "A", '"', "\n"], ["ä", "\n", '"', "A", "😀", ""], true],
  [["é"], ["é"], false],
])(
  "preserves exact string multiplicity and input order: %j / %j",
  (left, right, expected) => {
    const beforeLeft = [...left];
    const beforeRight = [...right];
    expect(sameStringMultiset(left, right)).toBe(expected);
    expect(sameStringMultiset(right, left)).toBe(expected);
    expect(left).toEqual(beforeLeft);
    expect(right).toEqual(beforeRight);
  },
);
