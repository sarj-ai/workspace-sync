import { z } from "zod";

const StringValueSchema = z.string();
const UnknownArraySchema = z.array(z.unknown());

export function sanitizedErrorFields(error: unknown): {
  "error_name": string;
  "stack_frames": string;
} {
  try {
    if (!(error instanceof Error)) return unknownErrorFields();
    return {
      "error_name": safeErrorName(error),
      "stack_frames": safeStackFrames(error),
    };
  } catch {
    return unknownErrorFields();
  }
}

export function safeErrorCodeChain(error: unknown): string {
  const pending: unknown[] = [error];
  const codes: string[] = [];
  const seen = new Set<unknown>();
  while (pending.length > 0 && codes.length < 8) {
    const candidate = pending.shift();
    if (candidate === undefined || candidate === null || seen.has(candidate))
      continue;
    seen.add(candidate);
    if (!(candidate instanceof Error)) continue;
    const message = safeErrorCode(candidate);
    if (message !== "" && !codes.includes(message)) codes.push(message);
    pending.push(...relatedErrors(candidate));
  }
  return codes.join(",");
}

function relatedErrors(error: Error): unknown[] {
  const related: unknown[] = [];
  if (error instanceof AggregateError) {
    const nested = UnknownArraySchema.safeParse(error.errors);
    if (nested.success) related.push(...nested.data);
  }
  try {
    related.push(error.cause);
  } catch {
    related.push(undefined);
  }
  return related;
}

function safeErrorCode(error: Error): string {
  try {
    const parsed = StringValueSchema.safeParse(error.message);
    return parsed.success && /^[a-z][a-z0-9_.:-]{0,127}$/u.test(parsed.data)
      ? parsed.data
      : "";
  } catch {
    return "";
  }
}

function unknownErrorFields() {
  return { "error_name": "UnknownError", "stack_frames": "" };
}

function safeErrorName(error: Error): string {
  try {
    const parsed = StringValueSchema.safeParse(error.constructor.name);
    return parsed.success && /^[A-Z][A-Za-z0-9]{0,63}$/.test(parsed.data)
      ? parsed.data
      : "UnknownError";
  } catch {
    return "UnknownError";
  }
}

function safeStackFrames(error: Error): string {
  let stack: unknown;
  try {
    stack = error.stack;
  } catch {
    return "";
  }
  const parsed = StringValueSchema.safeParse(stack);
  if (!parsed.success) return "";
  return parsed.data
    .split("\n")
    .slice(1)
    .flatMap((line) => {
      const match =
        /^\s*at (?:async )?(?:[\w.$<>-]+ )?\(?([^()\s]+):(\d+):(\d+)\)?$/.exec(
          line,
        );
      if (!match) return [];
      const [, , lineNumber, columnNumber] = match;
      return lineNumber && columnNumber ? `${lineNumber}:${columnNumber}` : [];
    })
    .slice(0, 12)
    .join("\n");
}
