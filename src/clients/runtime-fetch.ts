const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/* Keep cancellation active through body reads and return redirects without following them. */
export const runtimeFetch: typeof fetch = async (input, init) => {
  const timeout = AbortSignal.timeout(DEFAULT_REQUEST_TIMEOUT_MS);
  const callerSignal =
    init?.signal === undefined
      ? input instanceof Request
        ? input.signal
        : undefined
      : init.signal;
  const signal = callerSignal
    ? AbortSignal.any([callerSignal, timeout])
    : timeout;
  return globalThis.fetch(input, { ...init, redirect: "manual", signal });
};
