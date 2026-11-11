import { z } from "zod";

import { sha256 } from "../runtime/sha256.ts";
import { type JsonValue, JsonValueSchema } from "./schemas.ts";

const JsonObjectSchema = z.record(z.string(), z.unknown());

export function canonicalJson(value: JsonValue): string {
  const parsed = JsonValueSchema.parse(value);
  return serialize(parsed);
}

export async function sha256Hex(value: JsonValue): Promise<string> {
  return sha256(canonicalJson(value));
}

export function sameJson(left: JsonValue, right: JsonValue): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

export { bytesToHex } from "../runtime/sha256.ts";

export function hexToBytes(value: string): null | Uint8Array<ArrayBuffer> {
  if (!/^[a-f0-9]+$/.test(value) || value.length % 2 !== 0) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    const byte = Number.parseInt(value.slice(index, index + 2), 16);
    if (!Number.isFinite(byte)) return null;
    bytes[index / 2] = byte;
  }
  return bytes;
}

function serialize(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (!isJsonObject(value)) return JSON.stringify(value);
  return `{${Object.entries(value)
    .toSorted(([left], [right]) => left.localeCompare(right))
    .map(([key, child]) => `${JSON.stringify(key)}:${serialize(child)}`)
    .join(",")}}`;
}

function isJsonObject(value: JsonValue): value is Record<string, JsonValue> {
  return JsonObjectSchema.safeParse(value).success;
}
