import { describe, expect, it } from "vitest";

import { fetchPort } from "../src/runtime/fetch-port.ts";

describe("fetch port", () => {
  it("preserves request data without binding the stored implementation or following redirects", async () => {
    const controller = new AbortController();
    const init: RequestInit = {
      method: "POST",
      body: "synthetic",
      redirect: "follow",
      signal: controller.signal,
      headers: { authorization: "Bearer synthetic" },
    };
    const calls: {
      receiver: unknown;
      input: RequestInfo | URL;
      init: RequestInit | undefined;
    }[] = [];
    const implementation: typeof fetch = function (
      this: unknown,
      input,
      options,
    ) {
      calls.push({ receiver: this, input, init: options });
      return Promise.resolve(new Response(null, { status: 307 }));
    };
    const client = { send: fetchPort(implementation) };
    const result = await client.send("https://example.invalid/original", init);
    expect(result.status).toBe(307);
    expect(calls).toEqual([
      {
        receiver: undefined,
        input: "https://example.invalid/original",
        init: { ...init, redirect: "manual" },
      },
    ]);
    expect(init.redirect).toBe("follow");
    expect(calls[0]?.init?.signal).toBe(controller.signal);
  });
});
