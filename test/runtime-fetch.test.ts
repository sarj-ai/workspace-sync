import { afterEach, describe, expect, it, vi } from "vitest";

import { runtimeFetch } from "../src/clients/runtime-fetch.ts";

describe("runtimeFetch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("combines the caller deadline with the shared deadline", async () => {
    const controller = new AbortController();
    const reason = new Error("cancelled by caller");
    const fetchMock = vi.fn<typeof fetch>(async (_input, init) => {
      controller.abort(reason);
      expect(init?.signal?.aborted).toBe(true);
      expect(init?.signal?.reason).toBe(reason);
      return new Response("ok");
    });
    vi.stubGlobal("fetch", fetchMock);

    await runtimeFetch("https://example.com", { signal: controller.signal });

    const signal = fetchMock.mock.calls[0]?.[1]?.signal;
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal).not.toBe(controller.signal);
  });

  it("keeps caller cancellation connected after receiving response headers", async () => {
    const controller = new AbortController();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await runtimeFetch("https://example.com", { signal: controller.signal });
    controller.abort();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it("keeps the shared deadline connected after receiving response headers", async () => {
    const timeout = new AbortController();
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(timeout.signal);
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await runtimeFetch("https://example.com", {
      signal: new AbortController().signal,
    });
    timeout.abort();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it("preserves cancellation carried by a Request input", async () => {
    const controller = new AbortController();
    const request = new Request("https://example.com", {
      signal: controller.signal,
    });
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await runtimeFetch(request);
    controller.abort();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it("honors an explicit null signal override", async () => {
    const controller = new AbortController();
    const request = new Request("https://example.com", {
      signal: controller.signal,
    });
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await runtimeFetch(request, { signal: null });
    controller.abort();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(false);
  });

  it("adds the shared timeout when the caller does not supply a signal", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);

    await runtimeFetch("https://example.com");

    expect(fetchMock).toHaveBeenCalledExactlyOnceWith("https://example.com", {
      redirect: "manual",
      signal: expect.any(AbortSignal),
    });
  });

  it("keeps the global receiver when stored and called as an object method", async () => {
    const guardedFetch = new Proxy(fetch, {
      apply: (_target, receiver) => {
        if (receiver !== globalThis) throw new TypeError("illegal invocation");
        return Promise.resolve(new Response("ok"));
      },
    });
    vi.stubGlobal("fetch", guardedFetch);

    const client = { fetch: runtimeFetch };

    await expect(client.fetch("https://example.com")).resolves.toBeInstanceOf(
      Response,
    );
  });
});
