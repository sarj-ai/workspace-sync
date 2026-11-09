import { describe, expect, it, vi } from "vitest";

import { createGitHubConditionalReadFetch } from "../src/clients/github-conditional-read-fetch.ts";

const URL = "https://api.github.com/repos/example/core/collaborators";
const OPTIONS = {
  headers: {
    authorization: "Bearer reader",
    accept: "application/vnd.github+json",
  },
};
const DATA = [{ id: 1, permissions: { push: true } }];

function json(
  value: unknown = DATA,
  etag = '"first"',
  extra: HeadersInit = {},
) {
  const headers = new Headers(extra);
  headers.set("etag", etag);
  return Response.json(value, { headers });
}

async function jsonBody(read: typeof fetch): Promise<unknown> {
  const response = await read(URL, OPTIONS);
  return response.json();
}

describe("GitHub conditional reads", () => {
  it("disables credential forwarding even when the caller requests automatic redirects", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(new Request(input, init).redirect).toBe("manual");
      return new Response(null, {
        status: 307,
        headers: { location: "https://other.example/" },
      });
    });
    const response = await createGitHubConditionalReadFetch(fetchImpl)(URL, {
      ...OPTIONS,
      redirect: "follow",
    });
    expect(response.status).toBe(307);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("rejects and cancels a response beyond the read bound instead of buffering it", async () => {
    const cancel = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(
      async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array(2 * 1024 * 1024 + 1));
            },
            cancel,
          }),
          { headers: { etag: '"oversized"' } },
        ),
    );
    await expect(
      createGitHubConditionalReadFetch(fetchImpl)(URL, OPTIONS),
    ).rejects.toThrow("github_conditional_read_response_too_large");
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("accounts for response metadata in its retained-byte bound", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      json({}, '"small"', { "x-large-metadata": "a".repeat(2048) }),
    );
    const read = createGitHubConditionalReadFetch(fetchImpl, {
      maxBytes: 1024,
    });
    await read(URL, OPTIONS);
    await read(URL, OPTIONS);
    expect(
      new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).headers.has(
        "if-none-match",
      ),
    ).toBe(false);
  });

  it.each(["primary", "retry-after"] as const)(
    "honors the %s cooldown without sending another read or serving cached access",
    async (kind) => {
      const clock = vi.spyOn(Date, "now").mockReturnValue(1000);
      try {
        const fetchImpl = vi
          .fn<typeof fetch>()
          .mockResolvedValueOnce(json())
          .mockResolvedValueOnce(
            Response.json(
              { message: "rate limited" },
              {
                status: 403,
                headers:
                  kind === "primary"
                    ? { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "3" }
                    : { "retry-after": "2" },
              },
            ),
          )
          .mockResolvedValueOnce(json());
        const read = createGitHubConditionalReadFetch(fetchImpl);
        await read(URL, OPTIONS);
        const limited = await read(URL, OPTIONS);
        expect(limited.status).toBe(403);
        await expect(read(URL, OPTIONS)).rejects.toThrow(
          "github_api_read_rate_limit_cooldown",
        );
        expect(fetchImpl).toHaveBeenCalledTimes(2);
        clock.mockReturnValue(3001);
        await expect(jsonBody(read)).resolves.toEqual(DATA);
        expect(fetchImpl).toHaveBeenCalledTimes(3);
      } finally {
        clock.mockRestore();
      }
    },
  );

  it("keeps cooldowns credential-specific and permits the exempt rate-limit diagnostic", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({}, { status: 429, headers: { "retry-after": "60" } }),
      )
      .mockResolvedValueOnce(json())
      .mockResolvedValueOnce(Response.json({ resources: {} }));
    const read = createGitHubConditionalReadFetch(fetchImpl);
    await read(URL, OPTIONS);
    await read(URL, { headers: { authorization: "Bearer different-reader" } });
    await read("https://api.github.com/rate_limit", OPTIONS);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    await expect(read(URL, OPTIONS)).rejects.toThrow(
      "github_api_read_rate_limit_cooldown",
    );
  });

  it("binds a concurrent 304 to the exact representation that supplied its validator", async () => {
    const pending = Promise.withResolvers<Response>();
    const changed = [{ id: 2 }];
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json())
      .mockImplementationOnce(() => pending.promise)
      .mockResolvedValueOnce(json(changed, '"changed"'));
    const read = createGitHubConditionalReadFetch(fetchImpl);
    await read(URL, OPTIONS);
    const older = jsonBody(read);
    await expect(jsonBody(read)).resolves.toEqual(changed);
    pending.resolve(new Response(null, { status: 304 }));
    await expect(older).resolves.toEqual(DATA);
  });

  it.each([0, -1, Infinity, 513])(
    "rejects an invalid cache entry bound of %s",
    (maxEntries) => {
      expect(() =>
        createGitHubConditionalReadFetch(vi.fn(), { maxEntries }),
      ).toThrow(RangeError);
    },
  );

  it("revalidates every read with GitHub and returns an independently readable authorized 304 body", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json())
      .mockResolvedValueOnce(
        new Response(null, {
          status: 304,
          headers: { "x-ratelimit-remaining": "4999" },
        }),
      );
    const read = createGitHubConditionalReadFetch(fetchImpl);
    await expect(jsonBody(read)).resolves.toEqual(DATA);
    const second = await read(URL, OPTIONS);
    expect(second.status).toBe(200);
    expect(second.headers.get("x-ratelimit-remaining")).toBe("4999");
    await expect(second.json()).resolves.toEqual(DATA);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(
      new Request(fetchImpl.mock.calls[0]?.[0] ?? URL).headers.get(
        "if-none-match",
      ),
    ).toBeNull();
    expect(
      new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).headers.get(
        "if-none-match",
      ),
    ).toBe('"first"');
  });

  it("uses new bodies and validators when the provider reports changed access", async () => {
    const changed = [{ id: 1, permissions: { admin: true } }];
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json())
      .mockResolvedValueOnce(json(changed, '"changed"'))
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    const read = createGitHubConditionalReadFetch(fetchImpl);
    await read(URL, OPTIONS);
    await expect(jsonBody(read)).resolves.toEqual(changed);
    await expect(jsonBody(read)).resolves.toEqual(changed);
    expect(
      new Request(fetchImpl.mock.calls[2]?.[0] ?? URL).headers.get(
        "if-none-match",
      ),
    ).toBe('"changed"');
  });

  it.each(["authorization", "accept", "url"] as const)(
    "isolates cached data across %s boundaries",
    async (boundary) => {
      const fetchImpl = vi.fn<typeof fetch>(() => Promise.resolve(json()));
      const read = createGitHubConditionalReadFetch(fetchImpl);
      await read(URL, OPTIONS);
      await read(boundary === "url" ? `${URL}?page=2` : URL, {
        headers: {
          authorization:
            boundary === "authorization" ? "Bearer writer" : "Bearer reader",
          accept:
            boundary === "accept" ? "application/json" : OPTIONS.headers.accept,
        },
      });
      expect(
        new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).headers.get(
          "if-none-match",
        ),
      ).toBeNull();
    },
  );

  it.each([401, 403, 404, 500])(
    "never substitutes cached success for HTTP %i",
    async (status) => {
      const fetchImpl = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(json())
        .mockResolvedValueOnce(Response.json({ message: "denied" }, { status }))
        .mockResolvedValueOnce(json());
      const read = createGitHubConditionalReadFetch(fetchImpl);
      await read(URL, OPTIONS);
      const denied = await read(URL, OPTIONS);
      expect(denied.status).toBe(status);
      await expect(denied.json()).resolves.toEqual({ message: "denied" });
      await read(URL, OPTIONS);
      expect(
        new Request(fetchImpl.mock.calls[2]?.[0] ?? URL).headers.get(
          "if-none-match",
        ),
      ).toBeNull();
    },
  );

  it("uses a fail-closed cooldown for a 429 without provider timing headers", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json())
      .mockResolvedValueOnce(
        Response.json({ message: "limited" }, { status: 429 }),
      );
    const read = createGitHubConditionalReadFetch(fetchImpl);
    await read(URL, OPTIONS);
    const limited = await read(URL, OPTIONS);
    expect(limited.status).toBe(429);
    await expect(read(URL, OPTIONS)).rejects.toThrow(
      "github_api_read_rate_limit_cooldown",
    );
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("propagates network failure instead of serving cached access", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json())
      .mockRejectedValueOnce(new Error("offline"));
    const read = createGitHubConditionalReadFetch(fetchImpl);
    await read(URL, OPTIONS);
    await expect(read(URL, OPTIONS)).rejects.toThrow("offline");
  });

  it.each(["POST", "PUT", "DELETE", "PATCH"])(
    "leaves %s operations unconditional and uncached",
    async (method) => {
      const fetchImpl = vi.fn<typeof fetch>(() => Promise.resolve(json()));
      const read = createGitHubConditionalReadFetch(fetchImpl);
      await read(URL, OPTIONS);
      await read(URL, { ...OPTIONS, method });
      expect(
        new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).headers.get(
          "if-none-match",
        ),
      ).toBeNull();
      expect(new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).method).toBe(
        method,
      );
    },
  );

  it.each([
    "anonymous",
    "foreign-host",
    "caller-validator",
    "no-store",
    "no-etag",
    "vary-all",
  ] as const)(
    "does not cache or add validators to %s reads",
    async (scenario) => {
      const fetchImpl = vi.fn<typeof fetch>(() =>
        Promise.resolve(
          scenario === "no-etag"
            ? Response.json(DATA)
            : json(
                DATA,
                '"first"',
                scenario === "no-store"
                  ? { "cache-control": "no-store" }
                  : scenario === "vary-all"
                    ? { vary: "*" }
                    : {},
              ),
        ),
      );
      const read = createGitHubConditionalReadFetch(fetchImpl);
      const url =
        scenario === "foreign-host" ? "https://example.com/data" : URL;
      const options = {
        headers: {
          ...(scenario !== "anonymous" && OPTIONS.headers),
          ...(scenario === "caller-validator" && {
            "if-none-match": '"caller"',
          }),
        },
      };
      await read(url, options);
      await read(url, options);
      expect(
        new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).headers.get(
          "if-none-match",
        ),
      ).toBe(scenario === "caller-validator" ? '"caller"' : null);
    },
  );

  it("keeps the original caller abort signal active at the transport boundary", async () => {
    const controller = new AbortController();
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      controller.abort();
      expect(new Request(input).signal.aborted).toBe(true);
      expect(init?.signal?.aborted).toBe(true);
      throw new Error("aborted");
    });
    await expect(
      createGitHubConditionalReadFetch(fetchImpl)(URL, {
        ...OPTIONS,
        signal: controller.signal,
      }),
    ).rejects.toThrow("aborted");
  });

  it("bounds cache entries and evicts the least recently used response", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() => Promise.resolve(json()));
    const read = createGitHubConditionalReadFetch(fetchImpl, { maxEntries: 2 });
    await read(URL, OPTIONS);
    await read(`${URL}?page=2`, OPTIONS);
    await read(`${URL}?page=3`, OPTIONS);
    await read(URL, OPTIONS);
    expect(
      new Request(fetchImpl.mock.calls[3]?.[0] ?? URL).headers.get(
        "if-none-match",
      ),
    ).toBeNull();
  });

  it("does not retain responses beyond the configured byte bound", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() => Promise.resolve(json()));
    const read = createGitHubConditionalReadFetch(fetchImpl, { maxBytes: 1 });
    await read(URL, OPTIONS);
    await read(URL, OPTIONS);
    expect(
      new Request(fetchImpl.mock.calls[1]?.[0] ?? URL).headers.get(
        "if-none-match",
      ),
    ).toBeNull();
  });

  it("refuses a provider 304 without a matching cached body", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() =>
      Promise.resolve(new Response(null, { status: 304 })),
    );
    const response = await createGitHubConditionalReadFetch(fetchImpl)(
      URL,
      OPTIONS,
    );
    expect(response.status).toBe(304);
  });
});
