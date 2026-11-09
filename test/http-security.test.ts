import { once } from "node:events";
import { createServer } from "node:http";

import { describe, expect, it, vi } from "vitest";

import { fetchWithRetry } from "../src/org-sync/http.ts";

describe("authenticated HTTP boundaries", () => {
  it.each([0, -1, 1.5, Infinity, NaN, 2_147_483_648])(
    "rejects timeout %s before dispatch",
    async (timeoutMs) => {
      const fetchImpl = vi.fn<typeof fetch>();
      await expect(
        fetchWithRetry(
          "https://example.com",
          {},
          { fetchImpl, label: "timeout", timeoutMs },
        ),
      ).rejects.toThrow(RangeError);
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  it("does not retry or sleep after explicit caller cancellation", async () => {
    const controller = new AbortController();
    const sleep = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      controller.abort();
      throw new Error("secret-provider-error");
    });
    const result = fetchWithRetry(
      "https://example.com",
      { signal: controller.signal },
      { fetchImpl, sleep, label: "cancel-test" },
    );
    await expect(result).rejects.toThrow("cancel-test request cancelled");
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(sleep).not.toHaveBeenCalled();
  });

  it.each([301, 302, 303, 307, 308])(
    "does not forward credentials through an HTTP %s redirect",
    async (status) => {
      let forwarded = false;
      let originalRequests = 0;
      const server = createServer((request, response) => {
        if (request.url === "/destination") {
          forwarded = true;
          response.end("unexpected");
        } else {
          originalRequests++;
          response.writeHead(status, { location: "/destination" });
          response.end();
        }
      });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const address = server.address();
      // eslint-disable-next-line @sarj/no-runtime-typeof -- Node server.address returns a primitive for Unix sockets and an object for TCP sockets.
      if (address === null || typeof address === "string")
        throw new Error("Missing test server address");
      try {
        const result = await fetchWithRetry(
          `http://127.0.0.1:${String(address.port)}/source`,
          {
            method: "POST",
            body: "assertion=test-assertion",
            headers: { authorization: "Bearer test-token" },
          },
          { label: "redirect-security-test" },
        );
        expect(result.status).toBe(status);
        await result.body?.cancel();
        expect(forwarded).toBe(false);
        expect(originalRequests).toBe(1);
      } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
      }
    },
  );

  it("redacts arbitrary transport errors from exceptions and default logs", async () => {
    const log = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new Error("secret-sentinel"));
    const result = fetchWithRetry(
      "https://example.com",
      {},
      {
        fetchImpl,
        label: "transport-security-test",
        maxAttempts: 2,
        sleep: async () => undefined,
      },
    );
    await expect(result).rejects.toThrow(
      "transport-security-test network failure",
    );
    await expect(result).rejects.not.toHaveProperty("cause");
    expect(JSON.stringify(log.mock.calls)).not.toContain("secret-sentinel");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([0, -1, 1.5, 11, NaN, Infinity])(
    "rejects invalid retry bound %s before dispatch",
    async (maxAttempts) => {
      const fetchImpl = vi.fn<typeof fetch>();
      await expect(
        fetchWithRetry(
          "https://example.com",
          {},
          { fetchImpl, label: "bounds-test", maxAttempts },
        ),
      ).rejects.toThrow(RangeError);
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  it("stops an expired deadline before dispatch", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    await expect(
      fetchWithRetry(
        "https://example.com",
        {},
        { fetchImpl, label: "deadline-test", deadlineAt: Date.now() - 1 },
      ),
    ).rejects.toThrow("deadline exceeded");
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
