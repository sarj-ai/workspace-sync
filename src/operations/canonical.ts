import { z } from "zod";

import { type JsonValue, JsonValueSchema } from "./schemas.ts";

const ENCODER = new TextEncoder();
const JsonScalarSchema = z.union([z.null(), z.boolean(), z.string()]);
const JsonNumberSchema = z.number();
const JsonObjectSchema = z.record(z.string(), z.unknown());

export function canonicalJson(value: JsonValue): string {
  const parsed = JsonValueSchema.parse(value);
  return serialize(parsed);
}

export async function sha256Hex(value: JsonValue): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    ENCODER.encode(canonicalJson(value)),
  );
  return bytesToHex(new Uint8Array(digest));
}

export function sameJson(left: JsonValue, right: JsonValue): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function hexToBytes(value: string): null | Uint8Array {
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
  const scalar = JsonScalarSchema.safeParse(value);
  if (scalar.success) {
    return JSON.stringify(scalar.data);
  }
  const number = JsonNumberSchema.safeParse(value);
  if (number.success) {
    if (!Number.isFinite(number.data))
      throw new TypeError("Canonical JSON cannot contain non-finite numbers");
    return JSON.stringify(number.data);
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (!isJsonObject(value))
    throw new TypeError("Canonical JSON must contain JSON values");
  return `{${Object.entries(value)
    .toSorted(([left], [right]) => left.localeCompare(right))
    .map(([key, child]) => `${JSON.stringify(key)}:${serialize(child)}`)
    .join(",")}}`;
}

function isJsonObject(value: JsonValue): value is Record<string, JsonValue> {
  return JsonObjectSchema.safeParse(value).success;
}
