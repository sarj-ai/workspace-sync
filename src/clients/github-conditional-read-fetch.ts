import { readBoundedText } from "../runtime/read-bounded-text.ts";
import { runtimeFetch } from "./runtime-fetch.ts";

const MAX_ENTRIES = 512;
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

interface CachedResponse {
  readonly body: string;
  readonly bytes: number;
  readonly etag: string;
  readonly headers: readonly [string, string][];
}

export function createGitHubConditionalReadFetch(
  fetchImpl: typeof fetch = runtimeFetch,
  limits: { readonly maxBytes?: number; readonly maxEntries?: number } = {},
): typeof fetch {
  const maxBytes = limits.maxBytes ?? MAX_BYTES;
  const maxEntries = limits.maxEntries ?? MAX_ENTRIES;
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > MAX_BYTES ||
    !Number.isSafeInteger(maxEntries) ||
    maxEntries < 1 ||
    maxEntries > MAX_ENTRIES
  )
    throw new RangeError("github_conditional_read_cache_bound_invalid");
  const cache = new Map<string, CachedResponse>();
  const blockedUntil = new Map<string, number>();
  let bytes = 0;

  function assertReadCapacity(request: Request): void {
    if (
      !isGitHubRead(request) ||
      new URL(request.url).pathname === "/rate_limit"
    )
      return;
    const key = request.headers.get("authorization") ?? "";
    const deadline = blockedUntil.get(key);
    if (deadline !== undefined && Date.now() < deadline)
      throw new Error("github_api_read_rate_limit_cooldown");
    blockedUntil.delete(key);
  }

  async function send(request: Request): Promise<Response> {
    const response = await fetchImpl(request, {
      signal: request.signal,
      redirect: "manual",
    });
    observeReadCapacity(request, response);
    return response;
  }

  function observeReadCapacity(request: Request, response: Response): void {
    if (!isGitHubRead(request) || ![403, 429].includes(response.status)) return;
    const deadline = readRetryDeadline(
      response.headers,
      Date.now(),
      response.status,
    );
    if (deadline === null) return;
    const key = request.headers.get("authorization") ?? "";
    blockedUntil.set(key, Math.max(blockedUntil.get(key) ?? 0, deadline));
    while (blockedUntil.size > MAX_ENTRIES) {
      const oldest = blockedUntil.keys().next().value;
      if (oldest === undefined) break;
      blockedUntil.delete(oldest);
    }
  }

  function remove(key: string): void {
    const entry = cache.get(key);
    if (entry !== undefined) bytes -= entry.bytes;
    cache.delete(key);
  }

  function remember(key: string, entry: CachedResponse): void {
    remove(key);
    if (entry.bytes > Math.min(maxBytes, MAX_RESPONSE_BYTES)) return;
    cache.set(key, entry);
    bytes += entry.bytes;
    while (cache.size > maxEntries || bytes > maxBytes) {
      const oldest = cache.keys().next().value;
      if (oldest === undefined) break;
      remove(oldest);
    }
  }

  function revalidated(
    key: string,
    cached: CachedResponse,
    response: Response,
  ): Response {
    const headers = new Headers([...cached.headers]);
    for (const [name, value] of response.headers) headers.set(name, value);
    const entry = cacheEntry(
      key,
      cached.body,
      headers.get("etag") ?? cached.etag,
      headers,
    );
    if (canStore(headers)) remember(key, entry);
    else remove(key);
    return decodedResponse(entry.body, headers);
  }

  return async (input, init) => {
    const request = new Request(input, init);
    assertReadCapacity(request);
    if (!canRevalidate(request)) return send(request);
    const key = JSON.stringify([request.url, [...request.headers]]);
    const cached = cache.get(key);
    if (cached !== undefined) {
      cache.delete(key);
      cache.set(key, cached);
      request.headers.set("if-none-match", cached.etag);
    }
    const response = await send(request);
    if (response.status === 304 && cached !== undefined) {
      return revalidated(key, cached, response);
    }
    remove(key);
    const etag = response.headers.get("etag");
    if (
      response.status !== 200 ||
      response.redirected ||
      etag === null ||
      !canStore(response.headers)
    )
      return response;
    const body = await readBoundedText(
      response,
      MAX_RESPONSE_BYTES,
      () => new Error("github_conditional_read_response_too_large"),
    );
    remember(key, cacheEntry(key, body, etag, response.headers));
    return decodedResponse(body, response.headers);
  };
}

function cacheEntry(
  key: string,
  body: string,
  etag: string,
  responseHeaders: Headers,
): CachedResponse {
  const headers = [...responseHeaders];
  const metadata =
    key.length +
    etag.length +
    headers.reduce((sum, [name, value]) => sum + name.length + value.length, 0);
  return { body, bytes: (body.length + metadata) * 2, etag, headers };
}

function canRevalidate(request: Request): boolean {
  return (
    isGitHubRead(request) &&
    !request.headers.has("if-none-match") &&
    !request.headers.has("if-modified-since") &&
    !["no-store", "reload"].includes(request.cache ?? "")
  );
}

function isGitHubRead(request: Request): boolean {
  return (
    request.method === "GET" &&
    new URL(request.url).origin === "https://api.github.com" &&
    (request.headers.get("authorization") ?? "").trim() !== ""
  );
}

function readRetryDeadline(
  headers: Headers,
  now: number,
  status: number,
): null | number {
  const rawAfter = headers.get("retry-after");
  const after = rawAfter === null ? NaN : Number(rawAfter);
  const afterMs = Number.isFinite(after)
    ? now + after * 1000
    : Date.parse(rawAfter ?? "");
  const resetMs =
    headers.get("x-ratelimit-remaining") === "0"
      ? Number(headers.get("x-ratelimit-reset")) * 1000
      : NaN;
  const deadlines = [afterMs, resetMs].filter(
    (value) => Number.isFinite(value) && value > now,
  );
  if (deadlines.length > 0) return Math.max(...deadlines);
  return status === 429 ||
    headers.get("x-ratelimit-remaining") === "0" ||
    rawAfter !== null
    ? now + 60_000
    : null;
}

function canStore(headers: Headers): boolean {
  return (
    !/(?:^|,)\s*no-store\b/iu.test(headers.get("cache-control") ?? "") &&
    !(headers.get("vary") ?? "")
      .split(",")
      .some((value) => value.trim() === "*")
  );
}

function decodedResponse(body: string, original: Headers): Response {
  const headers = new Headers(original);
  for (const name of [
    "content-encoding",
    "content-length",
    "transfer-encoding",
  ])
    headers.delete(name);
  return new Response(body, { headers, status: 200 });
}

export const githubConditionalReadFetch = createGitHubConditionalReadFetch();
