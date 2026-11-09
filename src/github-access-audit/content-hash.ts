import { z } from "zod";

import { sha256 } from "../runtime/sha256.ts";

const JsonRecordSchema = z.record(z.string(), z.unknown());

export async function contentHash(value: unknown): Promise<string> {
  return sha256(stableStringify(value));
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).toSorted(compareString).join(",")}]`;
  }
  const object = JsonRecordSchema.safeParse(value);
  if (object.success) {
    return `{${Object.entries(object.data)
      .filter(([, item]) => item !== undefined)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function compareString(left: string, right: string): number {
  return left.localeCompare(right);
}
