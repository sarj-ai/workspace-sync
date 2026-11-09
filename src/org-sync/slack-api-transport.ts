import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { logEvent } from "../shared/log-event.ts";
import {
  defaultSleep,
  fetchWithRetry,
  RetryDeadlineExceededError,
  type RetryOptions,
  type Sleep,
} from "./http.ts";
import type { SlackMember } from "./model.ts";
import { waitForSlackRateLimit } from "./slack-rate-limit.ts";

const SLACK_API = "https://slack.com/api";
const MAX_SLACK_PAGES = 20;
const MAX_SLACK_RESPONSE_BYTES = 8 * 1024 * 1024;
const SLACK_RESPONSE_TIMEOUT_MS = 15_000;
const TRANSIENT_SLACK_ERRORS: ReadonlySet<string> = new Set([
  "fatal_error",
  "internal_error",
  "ratelimited",
  "request_timeout",
  "service_unavailable",
]);
const SlackErrorSchema = z.object({
  error: z.string().optional(),
  ok: z.literal(false),
});
const SlackFieldValueSchema = z.object({
  alt: z.string().optional(),
  value: z.string().optional(),
});
const SlackUserSchema = z.object({
  deleted: z.boolean().optional(),
  "enterprise_user": z
    .object({
      "is_admin": z.boolean().optional(),
      "is_owner": z.boolean().optional(),
      "is_primary_owner": z.boolean().optional(),
    })
    .optional(),
  id: z.string().regex(/^[UW][A-Z0-9]+$/),
  "is_admin": z.boolean().optional(),
  "is_app_user": z.boolean().optional(),
  "is_bot": z.boolean().optional(),
  "is_owner": z.boolean().optional(),
  "is_primary_owner": z.boolean().optional(),
  "is_restricted": z.boolean().optional(),
  "is_ultra_restricted": z.boolean().optional(),
  profile: z.object({
    "display_name": z.string().optional(),
    email: z.email().optional(),
    fields: z.record(z.string(), SlackFieldValueSchema).optional(),
    "real_name": z.string().optional(),
    title: z.string().optional(),
  }),
  "team_id": z.string().optional(),
});
const UsersPageSchema = z.object({
  members: z.array(SlackUserSchema),
  ok: z.literal(true),
  "response_metadata": z
    .object({ "next_cursor": z.string().optional() })
    .optional(),
});

export interface SlackApiTransportOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  token: string;
}

export interface SlackCallResult {
  body: unknown;
  response: Response;
}

export class SlackWriteOutcomeUnknownError extends Error {
  override name = "SlackWriteOutcomeUnknownError";
}
export class SlackRateLimitedError extends Error {
  override name = "SlackRateLimitedError";
}

export function parseSlackWriteResponse<T extends z.ZodType>(
  schema: T,
  body: unknown,
  method: string,
): z.output<T> {
  const result = schema.safeParse(body);
  if (!result.success) {
    throw new SlackWriteOutcomeUnknownError(
      `Slack ${method} returned an invalid write response`,
      {
        cause: result.error,
      },
    );
  }
  return result.data;
}

export interface SlackApiCaller {
  call(
    method: string,
    data: Record<string, unknown>,
    runId: string,
    options?: { deadlineAt?: number | undefined; post?: boolean | undefined },
  ): Promise<SlackCallResult>;
  listUsers(runId: string, deadlineAt?: number): Promise<SlackMember[]>;
}

export class SlackApiTransport implements SlackApiCaller {
  readonly #fetchImpl: typeof fetch;
  readonly #random: (() => number) | undefined;
  readonly #sleep: Sleep | undefined;
  readonly #token: string;

  constructor(options: SlackApiTransportOptions) {
    this.#fetchImpl = options.fetchImpl ?? runtimeFetch;
    this.#random = options.random;
    this.#sleep = options.sleep;
    this.#token = options.token;
  }

  async call(
    method: string,
    data: Record<string, unknown>,
    runId: string,
    options: {
      deadlineAt?: number | undefined;
      post?: boolean | undefined;
    } = {},
  ): Promise<SlackCallResult> {
    const post = options.post ?? false;
    const deadlineAt = options.deadlineAt ?? Date.now() + 60_000;
    const attempts = post ? 1 : 3;
    const sleep = this.#sleep ?? defaultSleep;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      // eslint-disable-next-line no-await-in-loop -- Each retry decision depends on the preceding Slack response.
      const result = await this.#requestWithWriteClassification(
        method,
        data,
        runId,
        post,
        deadlineAt,
      );
      const parsed = SlackErrorSchema.safeParse(result.body);
      if (!parsed.success) return result;
      // eslint-disable-next-line no-await-in-loop -- Retry-After must elapse before the next Slack request.
      await retrySlackApplicationError({
        attempt,
        attempts,
        deadlineAt,
        method,
        post,
        random: this.#random ?? Math.random,
        response: result.response,
        runId,
        slackErrorCode: parsed.data.error ?? "unknown",
        sleep,
      });
    }
    throw new Error(`Slack ${method} failed after retries`);
  }

  async listUsers(runId: string, deadlineAt?: number): Promise<SlackMember[]> {
    const members: SlackMember[] = [];
    const seenCursors = new Set<string>();
    let cursor = "";
    let page = 0;
    do {
      page++;
      if (page > MAX_SLACK_PAGES)
        throw new Error("Slack users.list exceeded page limit");
      if (cursor && seenCursors.has(cursor))
        throw new Error("Slack users.list repeated a cursor");
      if (cursor) seenCursors.add(cursor);
      const params: Record<string, string> = { limit: "200" };
      if (cursor) params.cursor = cursor;
      // eslint-disable-next-line no-await-in-loop -- Each users.list cursor is returned by the preceding page.
      const response = await this.call("users.list", params, runId, {
        deadlineAt,
      });
      const parsed = UsersPageSchema.parse(response.body);
      members.push(...parsed.members);
      cursor = parsed["response_metadata"]?.["next_cursor"]?.trim() ?? "";
      logEvent("org_sync.slack_page", {
        count: parsed.members.length,
        page,
        "run_id": runId,
      });
    } while (cursor);
    return members;
  }

  async #requestWithWriteClassification(
    method: string,
    data: Record<string, unknown>,
    runId: string,
    post: boolean,
    deadlineAt: number,
  ): Promise<SlackCallResult> {
    try {
      return await this.#request(method, data, runId, post, deadlineAt);
    } catch (error) {
      if (post && ambiguousWriteFailure(error)) {
        throw new SlackWriteOutcomeUnknownError(toErrorMessage(error), {
          cause: error,
        });
      }
      throw error;
    }
  }

  async #request(
    method: string,
    data: Record<string, unknown>,
    runId: string,
    post: boolean,
    deadlineAt: number,
  ): Promise<SlackCallResult> {
    const query = new URLSearchParams();
    if (!post)
      for (const [key, value] of Object.entries(data))
        query.set(key, String(value));
    const response = await fetchWithRetry(
      `${SLACK_API}/${method}${post ? "" : `?${query.toString()}`}`,
      post
        ? {
            body: JSON.stringify(data),
            headers: {
              authorization: `Bearer ${this.#token}`,
              "content-type": "application/json; charset=utf-8",
            },
            method: "POST",
            redirect: "manual",
          }
        : {
            headers: { authorization: `Bearer ${this.#token}` },
            redirect: "manual",
          },
      {
        deadlineAt,
        fetchImpl: this.#fetchImpl,
        label: `slack.${method}`,
        maxAttempts: post ? 1 : 3,
        random: this.#random,
        respectRetryAfter: true,
        runId,
        sleep: this.#sleep,
      },
    );
    if (post && response.status === 429) {
      await response.body?.cancel();
      return { body: { error: "ratelimited", ok: false }, response };
    }
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(`Slack ${method} HTTP ${String(response.status)}`);
    }
    try {
      return {
        body: await readBoundedSlackResponse(response, method, deadlineAt),
        response,
      };
    } catch (error) {
      if (post) {
        throw new SlackWriteOutcomeUnknownError(
          `Slack ${method} response unreadable after POST`,
          {
            cause: error,
          },
        );
      }
      throw error;
    }
  }
}

async function readBoundedSlackResponse(
  response: { readonly body: ReadableStream<Uint8Array> | null },
  method: string,
  deadlineAt: number,
): Promise<unknown> {
  if (response.body === null)
    throw new Error(`Slack ${method} returned an empty response`);
  const remainingMs = Math.min(
    SLACK_RESPONSE_TIMEOUT_MS,
    deadlineAt - Date.now(),
  );
  if (remainingMs <= 0)
    throw new RetryDeadlineExceededError({ label: `slack.${method}` });
  const signal = AbortSignal.timeout(remainingMs);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parts: string[] = [];
  let bytes = 0;
  const { promise: deadline, reject: rejectDeadline } =
    Promise.withResolvers<never>();
  const onAbort = () =>
    rejectDeadline(
      new RetryDeadlineExceededError({ label: `slack.${method}` }),
    );
  signal.addEventListener("abort", onAbort, { once: true });
  let completed = false;
  try {
    let chunk = await Promise.race([reader.read(), deadline]);
    while (!chunk.done) {
      bytes += chunk.value.byteLength;
      if (bytes > MAX_SLACK_RESPONSE_BYTES) {
        throw new Error(`Slack ${method} response exceeds size limit`);
      }
      parts.push(decoder.decode(chunk.value, { stream: true }));
      // eslint-disable-next-line no-await-in-loop -- Each chunk must be bounded before the next read.
      chunk = await Promise.race([reader.read(), deadline]);
    }
    parts.push(decoder.decode());
    const parsed: unknown = JSON.parse(parts.join(""));
    completed = true;
    return parsed;
  } finally {
    signal.removeEventListener("abort", onAbort);
    if (!completed) void reader.cancel().catch(() => undefined);
    else reader.releaseLock();
  }
}

async function retrySlackApplicationError(input: {
  attempt: number;
  attempts: number;
  deadlineAt?: number | undefined;
  method: string;
  post: boolean;
  random: () => number;
  response: Response;
  runId: string;
  slackErrorCode: string;
  sleep: Sleep;
}): Promise<void> {
  if (
    input.post &&
    input.slackErrorCode === "ratelimited" &&
    input.response.status === 429
  ) {
    const waitMs = input.response.headers.get("retry-after") ?? "default";
    logEvent("org_sync.slack_rate_limit_retry", {
      attempt: input.attempt,
      method: input.method,
      "retry_after": waitMs,
      "run_id": input.runId,
    });
    await waitForSlackRateLimit({
      deadlineAt: input.deadlineAt,
      label: `Slack ${input.method}`,
      response: input.response,
      sleep: input.sleep,
    });
    throw new SlackRateLimitedError(
      `Slack ${input.method} HTTP 429; retry requires fresh authority capture`,
    );
  }
  if (input.post && TRANSIENT_SLACK_ERRORS.has(input.slackErrorCode)) {
    throw new SlackWriteOutcomeUnknownError(
      `Slack ${input.method} error: ${input.slackErrorCode}`,
    );
  }
  if (
    input.post ||
    !TRANSIENT_SLACK_ERRORS.has(input.slackErrorCode) ||
    input.attempt === input.attempts
  ) {
    throw new Error(`Slack ${input.method} error: ${input.slackErrorCode}`);
  }
  const waitMs = Math.max(250, Math.floor(input.random() * 2_000));
  if (
    input.deadlineAt !== undefined &&
    Date.now() + waitMs >= input.deadlineAt
  ) {
    throw new Error(`Slack ${input.method} deadline exceeded before retry`);
  }
  logEvent("org_sync.slack_application_retry", {
    attempt: input.attempt,
    error: input.slackErrorCode,
    method: input.method,
    "run_id": input.runId,
    "wait_ms": waitMs,
  });
  await input.sleep(waitMs);
}

function ambiguousWriteFailure(error: unknown): boolean {
  const message = toErrorMessage(error);
  const statusMatch = / HTTP (\d{3})$/.exec(message);
  if (statusMatch) {
    const status = Number(statusMatch[1]);
    return status === 408 || status >= 500;
  }
  return (
    message.includes("network failure") || message.includes("deadline exceeded")
  );
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
