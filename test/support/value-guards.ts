import { z } from "zod";

const StringSchema = z.string();

export function isString(value: unknown): value is string {
  return StringSchema.safeParse(value).success;
}
