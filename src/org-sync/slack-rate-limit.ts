import type { Sleep } from "./http.ts";

const DEFAULT_SLACK_RATE_LIMIT_WAIT_MS = 1_000;

export function slackRetryAfterMs(response: Response): number {
  const value = response.headers.get("retry-after")?.trim();
  if (value && /^\d+(?:\.\d+)?$/u.test(value)) {
    const milliseconds = Number(value) * 1_000;
    if (Number.isFinite(milliseconds))
      return Math.max(1, Math.ceil(milliseconds));
  }
  if (value) {
    const retryAt = Date.parse(value);
    if (Number.isFinite(retryAt)) return Math.max(1, retryAt - Date.now());
  }
  return DEFAULT_SLACK_RATE_LIMIT_WAIT_MS;
}

export async function waitForSlackRateLimit(input: {
  deadlineAt?: number | undefined;
  label: string;
  response: Response;
  sleep: Sleep;
}): Promise<void> {
  const waitMs = slackRetryAfterMs(input.response);
  if (
    input.deadlineAt !== undefined &&
    Date.now() + waitMs >= input.deadlineAt
  ) {
    throw new Error(`${input.label} deadline exceeded before rate-limit retry`);
  }
  await input.sleep(waitMs);
}
