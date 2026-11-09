import { fetchWithRetry, type RetryOptions } from "./http.ts";

/* Keep the authenticated principal and billing project authoritative over extra headers. */
export function googleApiRequest(
  url: string,
  token: string,
  userProject: string,
  init: RequestInit,
  retry: RetryOptions,
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${token}`);
  headers.set("x-goog-user-project", userProject);
  return fetchWithRetry(url, { ...init, headers }, retry);
}
