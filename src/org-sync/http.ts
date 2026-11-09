import { logEvent } from "../shared/log-event.ts";

export type Sleep = (
  milliseconds: number,
  signal?: AbortSignal,
) => Promise<void>;

export const defaultSleep: Sleep = async (milliseconds, signal) => {
  if (
    !Number.isSafeInteger(milliseconds) ||
    milliseconds < 0 ||
    milliseconds > 2_147_483_647
  ) {
    throw new RangeError("Delay must be a nonnegative signed 32-bit integer");
  }
  if (signal?.aborted) throw new Error("HTTP retry delay cancelled");
  return new Promise<void>((resolve, reject) => {
    const cleanup = (): void => signal?.removeEventListener("abort", abort);
    const abort = (): void => {
      clearTimeout(timer);
      cleanup();
      reject(new Error("HTTP retry delay cancelled"));
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  });
};

export interface RetryOptions {
  deadlineAt?: number | undefined;
  fetchImpl?: typeof fetch | undefined;
  label: string;
  maxAttempts?: number | undefined;
  random?: (() => number) | undefined;
  respectRetryAfter?: boolean | undefined;
  retryError?: ((error: unknown) => boolean) | undefined;
  runId?: string | undefined;
  sleep?: Sleep | undefined;
  timeoutMs?: number | undefined;
}

export class RetryDeadlineExceededError extends Error {
  constructor(options: ErrorOptions & { detail?: string; label: string }) {
    super(`${options.label} deadline exceeded${options.detail ?? ""}`, options);
    this.name = "RetryDeadlineExceededError";
  }
}

/* Retry transient failures within a bounded budget. Callers validate HTTP status;
 * redirect responses are returned without forwarding credentials or request bodies.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  options: RetryOptions,
): Promise<Response> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxAttempts = validateRetryOptions(options);
  const random = options.random ?? Math.random;
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      defaultSleep(milliseconds, init.signal ?? undefined));

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (init.signal?.aborted)
      throw new Error(`${options.label} request cancelled`);
    let response: Response;
    try {
      // eslint-disable-next-line no-await-in-loop -- Each retry decision depends on the preceding network attempt.
      response = await fetchAttempt(fetchImpl, url, init, options);
    } catch (error) {
      if (init.signal?.aborted)
        throw new Error(`${options.label} request cancelled`);
      // eslint-disable-next-line no-await-in-loop -- Network backoff must finish before the next retry attempt.
      const retry = await continueAfterNetworkFailure(
        error,
        attempt,
        maxAttempts,
        options,
        random,
        sleep,
      );
      if (!retry) break;
      continue;
    }
    if (!transientStatus(response.status) || attempt === maxAttempts)
      return response;
    // eslint-disable-next-line no-await-in-loop -- Retry-After and response-body cleanup must finish before the next request.
    await waitForHttpRetry(response, attempt, options, random, sleep);
  }
  throw new Error(`${options.label} network failure`);
}

function validateRetryOptions(options: RetryOptions): number {
  const maxAttempts = options.maxAttempts ?? 3;
  if (
    !Number.isSafeInteger(maxAttempts) ||
    maxAttempts < 1 ||
    maxAttempts > 10
  ) {
    throw new RangeError(
      "HTTP retry attempts must be an integer between 1 and 10",
    );
  }
  if (
    options.timeoutMs !== undefined &&
    (!Number.isSafeInteger(options.timeoutMs) ||
      options.timeoutMs < 1 ||
      options.timeoutMs > 2_147_483_647)
  )
    throw new RangeError(
      "HTTP timeout must be a positive signed 32-bit integer",
    );
  if (options.deadlineAt !== undefined && !Number.isFinite(options.deadlineAt))
    throw new RangeError("HTTP deadline must be finite");
  return maxAttempts;
}

async function continueAfterNetworkFailure(
  error: unknown,
  attempt: number,
  maxAttempts: number,
  options: RetryOptions,
  random: () => number,
  sleep: Sleep,
): Promise<boolean> {
  if (
    error instanceof RetryDeadlineExceededError ||
    options.retryError?.(error) === false
  )
    throw error;
  if (attempt === maxAttempts) return false;
  await waitForNetworkRetry(attempt, options, random, sleep);
  return true;
}

function transientStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function remainingBudget(options: RetryOptions): number {
  if (options.deadlineAt === undefined) return Infinity;
  const remaining = options.deadlineAt - Date.now();
  if (remaining <= 0)
    throw new RetryDeadlineExceededError({ label: options.label });
  return remaining;
}

async function waitForHttpRetry(
  response: Response,
  attempt: number,
  options: RetryOptions,
  random: () => number,
  sleep: Sleep,
): Promise<void> {
  const requestedWaitMs = retryDelay(
    response,
    attempt - 1,
    random,
    options.respectRetryAfter ?? false,
  );
  const budgetMs = remainingBudget(options);
  if (options.respectRetryAfter === true && requestedWaitMs >= budgetMs) {
    await response.body?.cancel();
    throw new RetryDeadlineExceededError({
      label: options.label,
      detail: " before HTTP retry",
    });
  }
  const waitMs = Math.min(requestedWaitMs, budgetMs);
  logEvent("org_sync.http_retry", {
    attempt,
    label: options.label,
    "run_id": options.runId,
    status: response.status,
    "wait_ms": waitMs,
  });
  await response.body?.cancel();
  await sleep(waitMs);
  remainingBudget(options);
}

function retryDelay(
  response: Response,
  attempt: number,
  random: () => number,
  respectRetryAfter: boolean,
): number {
  const retryAfterHeader = response.headers.get("retry-after");
  const retryAfterSeconds = Number(retryAfterHeader);
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
    return respectRetryAfter
      ? retryAfterSeconds * 1_000
      : Math.min(8000, retryAfterSeconds * 1_000);
  }
  const retryAfterDate =
    retryAfterHeader === null ? NaN : Date.parse(retryAfterHeader);
  if (Number.isFinite(retryAfterDate)) {
    const retryAfterMilliseconds = retryAfterDate - Date.now();
    if (retryAfterMilliseconds > 0)
      return respectRetryAfter
        ? retryAfterMilliseconds
        : Math.min(8000, retryAfterMilliseconds);
  }
  const ceiling = Math.min(8000, 500 * 2 ** attempt);
  return Math.max(100, Math.floor(random() * ceiling));
}

async function waitForNetworkRetry(
  attempt: number,
  options: RetryOptions,
  random: () => number,
  sleep: Sleep,
): Promise<void> {
  const jitterMs = Math.max(
    100,
    Math.floor(random() * Math.min(8000, 500 * 2 ** (attempt - 1))),
  );
  const waitMs = Math.min(jitterMs, remainingBudget(options));
  logEvent("org_sync.network_retry", {
    attempt,
    label: options.label,
    "run_id": options.runId,
    "wait_ms": waitMs,
  });
  await sleep(waitMs);
  remainingBudget(options);
}

async function fetchAttempt(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  options: RetryOptions,
): Promise<Response> {
  const timeoutMs = Math.min(
    options.timeoutMs ?? 15_000,
    remainingBudget(options),
  );
  return fetchImpl(url, attemptInit(init, timeoutMs));
}

function attemptInit(init: RequestInit, timeoutMs: number): RequestInit {
  // Authenticated API calls must never forward JWT assertions or request bodies
  // to a redirect destination. Manual redirects remain visible to the caller.
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  if (!init.signal)
    return { ...init, redirect: "manual", signal: timeoutSignal };
  return {
    ...init,
    redirect: "manual",
    signal: AbortSignal.any([init.signal, timeoutSignal]),
  };
}
