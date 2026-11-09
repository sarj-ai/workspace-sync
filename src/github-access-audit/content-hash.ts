import { z } from "zod";

const JsonRecordSchema = z.record(z.string(), z.unknown());

export async function contentHash(value: unknown): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(stableStringify(value)),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
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
