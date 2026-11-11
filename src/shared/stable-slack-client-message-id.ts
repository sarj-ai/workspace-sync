import { z } from "zod";
const DeliveryKeySchema = z.string().regex(/^[a-z0-9]+(?:[./:-][a-z0-9]+)*$/u);
export async function stableSlackClientMessageId(key: string): Promise<string> {
  DeliveryKeySchema.parse(key);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)),
  ).slice(0, 16);
  digest[6] = ((digest[6] ?? 0) & 0x0f) | 0x50;
  digest[8] = ((digest[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...digest]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
