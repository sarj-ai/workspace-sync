import { z } from "zod";

import {
  type DownstreamAccount,
  normalizeEmail,
} from "../access-guard/model.ts";
import { runtimeFetch } from "../clients/runtime-fetch.ts";

const EmailSchema = z.email().transform(normalizeEmail);
const UserSchema = z.object({
  email: EmailSchema,
  globalRole: z.enum([
    "Organization Admin",
    "Elevated Access",
    "Limited Access",
    "External Recruiter",
  ]),
  id: z.uuid(),
  isEnabled: z.boolean(),
});
const PageSchema = z.object({
  moreDataAvailable: z.boolean(),
  nextCursor: z.string().trim().min(1).optional(),
  results: z.array(UserSchema).max(100),
  success: z.literal(true),
});
const MAX_PAGES = 20;
const MAX_RESPONSE_BYTES = 1024 * 1024;

export async function readAshbyOffboardingAccounts(
  input: { apiKey: string; expectedRootEmail: string },
  fetchImpl: typeof fetch = runtimeFetch,
): Promise<readonly DownstreamAccount[]> {
  if (!input.apiKey.trim())
    throw new Error("ashby_offboarding_credentials_missing");
  const rootEmail = EmailSchema.parse(input.expectedRootEmail);
  const deadline = AbortSignal.timeout(60_000);
  const users: z.output<typeof UserSchema>[] = [];
  const cursors = new Set<string>();
  let cursor = "start";
  for (let pageNumber = 0; pageNumber < MAX_PAGES; pageNumber += 1) {
    if (cursors.has(cursor)) throw new Error("ashby_offboarding_cursor_cycle");
    cursors.add(cursor);
    // eslint-disable-next-line no-await-in-loop -- Pagination requires the previous page's cursor.
    const response = await fetchPage(fetchImpl, {
      body: JSON.stringify({ cursor, includeDeactivated: true, limit: 100 }),
      headers: {
        authorization: `Basic ${btoa(`${input.apiKey}:`)}`,
        "content-type": "application/json",
      },
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.any([deadline, AbortSignal.timeout(15_000)]),
    });
    if (!response.ok) {
      // eslint-disable-next-line no-await-in-loop -- Cancel this failed response before rejecting the inventory.
      await response.body?.cancel();
      throw new Error(httpFailureCode(response.status));
    }
    // eslint-disable-next-line no-await-in-loop -- A page must validate before consuming its continuation.
    const body = await boundedJson(response, deadline);
    const page = parsePage(body);
    users.push(...page.results);
    if (!page.moreDataAvailable) return verifyInventory(users, rootEmail);
    if (!page.nextCursor) throw new Error("ashby_offboarding_cursor_missing");
    cursor = page.nextCursor;
  }
  throw new Error("ashby_offboarding_page_bound");
}

async function fetchPage(
  fetchImpl: typeof fetch,
  init: RequestInit,
): Promise<Response> {
  try {
    return await fetchImpl("https://api.ashbyhq.com/user.list", init);
  } catch (error) {
    throw transportFailure(error, init.signal);
  }
}

function httpFailureCode(status: number): string {
  if (status === 401 || status === 403) return "ashby_offboarding_auth_failed";
  if (status === 404) return "ashby_offboarding_endpoint_not_found";
  if (status === 429) return "ashby_offboarding_rate_limited";
  if (status >= 500) return "ashby_offboarding_service_unavailable";
  return "ashby_offboarding_request_rejected";
}

function transportFailure(error: unknown, signal?: AbortSignal | null): Error {
  const timedOut =
    signal?.aborted === true ||
    (error instanceof Error &&
      (error.name === "TimeoutError" || error.name === "AbortError"));
  return new Error(
    timedOut ? "ashby_offboarding_timeout" : "ashby_offboarding_network_failed",
  );
}

function parsePage(body: unknown) {
  if (z.object({ success: z.literal(false) }).safeParse(body).success)
    throw new Error("ashby_offboarding_request_rejected");
  return PageSchema.parse(body);
}

async function boundedJson(
  response: Response,
  signal: AbortSignal,
): Promise<unknown> {
  if (response.body === null)
    throw new Error("ashby_offboarding_response_empty");
  let bytes = 0;
  const bounded = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        bytes += chunk.byteLength;
        if (bytes > MAX_RESPONSE_BYTES)
          throw new Error("ashby_offboarding_response_bound");
        controller.enqueue(chunk);
      },
    }),
    { signal },
  );
  try {
    const body = await new Response(bounded).text();
    if (body.length === 0) throw new Error("ashby_offboarding_response_empty");
    try {
      return JSON.parse(body);
    } catch {
      throw new Error("ashby_offboarding_invalid_json");
    }
  } catch (error) {
    if (
      error instanceof Error &&
      [
        "ashby_offboarding_response_empty",
        "ashby_offboarding_response_bound",
        "ashby_offboarding_invalid_json",
      ].includes(error.message)
    )
      throw error;
    throw transportFailure(error, signal);
  }
}

function verifyInventory(
  users: readonly z.output<typeof UserSchema>[],
  rootEmail: string,
): readonly DownstreamAccount[] {
  if (
    new Set(users.map((user) => user.id)).size !== users.length ||
    new Set(users.map((user) => user.email)).size !== users.length
  ) {
    throw new Error("ashby_offboarding_duplicate_identity");
  }
  if (
    !users.some(
      (user) =>
        user.email === rootEmail &&
        user.isEnabled &&
        user.globalRole === "Organization Admin",
    )
  ) {
    throw new Error("ashby_offboarding_root_anchor_missing");
  }
  return users.map((user) => ({
    active: user.isEnabled,
    email: user.email,
    id: user.id,
  }));
}
