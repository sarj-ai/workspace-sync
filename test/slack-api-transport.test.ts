import { describe, expect, it, vi } from "vitest";

import {
  SlackApiTransport,
  SlackRateLimitedError,
  SlackWriteOutcomeUnknownError,
} from "../src/org-sync/slack-api-transport.ts";

function json(
  body: unknown,
  status = 200,
  headers: HeadersInit = {},
): Response {
  return Response.json(body, { headers, status });
}

function transport(fetchImpl: typeof fetch) {
  const sleep = vi.fn(async () => undefined);
  return {
    client: new SlackApiTransport({ fetchImpl, sleep, token: "xoxb-test" }),
    sleep,
  };
}

describe("SlackApiTransport POST rate limits", () => {
  it("honors Retry-After but requires fresh authority capture after HTTP 429", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      json({ error: "ratelimited", ok: false }, 429, { "retry-after": "17" }),
    );
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call("usergroups.users.update", { users: "U1" }, "run-1", {
        post: true,
      }),
    ).rejects.toBeInstanceOf(SlackRateLimitedError);

    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fixture.sleep).toHaveBeenCalledOnce();
    expect(fixture.sleep).toHaveBeenCalledWith(17_000);
  });

  it("uses a bounded default wait when Retry-After is missing", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      json({ error: "ratelimited", ok: false }, 429),
    );
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call("usergroups.users.update", { users: "U1" }, "run-1", {
        post: true,
      }),
    ).rejects.toBeInstanceOf(SlackRateLimitedError);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fixture.sleep).toHaveBeenCalledWith(1_000);
  });

  it("does not replay a POST after an ambiguous HTTP 500 response", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => json({ ok: false }, 500));
    const fixture = transport(fetchImpl);

    const result = fixture.client.call(
      "usergroups.users.update",
      { users: "U1" },
      "run-1",
      {
        post: true,
      },
    );

    await expect(result).rejects.toBeInstanceOf(SlackWriteOutcomeUnknownError);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fixture.sleep).not.toHaveBeenCalled();
  });

  it("does not replay a POST after an ambiguous network failure", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      throw new TypeError("network down");
    });
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call("usergroups.users.update", { users: "U1" }, "run-1", {
        post: true,
      }),
    ).rejects.toBeInstanceOf(SlackWriteOutcomeUnknownError);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fixture.sleep).not.toHaveBeenCalled();
  });

  it.each([
    { name: "malformed JSON", response: () => new Response("{invalid") },
    {
      name: "oversized JSON",
      response: () => new Response("x".repeat(8 * 1024 * 1024 + 1)),
    },
  ])(
    "does not replay a POST after a 200 $name response",
    async ({ response }) => {
      const fetchImpl = vi.fn<typeof fetch>(async () => response());
      const fixture = transport(fetchImpl);

      await expect(
        fixture.client.call(
          "conversations.kick",
          { channel: "C1", user: "U1" },
          "run-1",
          {
            post: true,
          },
        ),
      ).rejects.toBeInstanceOf(SlackWriteOutcomeUnknownError);
      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(fixture.sleep).not.toHaveBeenCalled();
    },
  );

  it("bounds a stalled 200 POST response by the caller deadline without replay", async () => {
    const cancel = vi.fn();
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response(new ReadableStream({ cancel })),
    );
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call(
        "conversations.kick",
        { channel: "C1", user: "U1" },
        "run-1",
        {
          deadlineAt: Date.now() + 50,
          post: true,
        },
      ),
    ).rejects.toBeInstanceOf(SlackWriteOutcomeUnknownError);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("keeps a deterministic HTTP 400 out of ambiguous-write handling", async () => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response("bad request", { status: 400 }),
    );
    const fixture = transport(fetchImpl);
    const result = fixture.client.call(
      "conversations.kick",
      { channel: "C1", user: "U1" },
      "run-1",
      {
        post: true,
      },
    );

    await expect(result).rejects.toThrow("Slack conversations.kick HTTP 400");
    await expect(result).rejects.not.toBeInstanceOf(
      SlackWriteOutcomeUnknownError,
    );
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("does not retry when Retry-After would consume the caller deadline", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      json({ error: "ratelimited", ok: false }, 429, { "retry-after": "60" }),
    );
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call("usergroups.users.update", { users: "U1" }, "run-1", {
        deadlineAt: Date.now() + 30_000,
        post: true,
      }),
    ).rejects.toThrow("deadline exceeded before rate-limit retry");
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fixture.sleep).not.toHaveBeenCalled();
  });
});

describe("SlackApiTransport read rate limits", () => {
  it("honors the full numeric Retry-After within the read deadline", async () => {
    const responses = [
      json({ error: "ratelimited", ok: false }, 429, { "retry-after": "17" }),
      json({ ok: true }),
    ];
    const fetchImpl = vi.fn<typeof fetch>(
      async () => responses.shift() ?? json({ ok: false }),
    );
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call("users.list", {}, "run-1"),
    ).resolves.toMatchObject({
      body: { ok: true },
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fixture.sleep).toHaveBeenCalledWith(17_000);
  });

  it("does not retry when the provider delay would consume the read deadline", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      json({ error: "ratelimited", ok: false }, 429, { "retry-after": "61" }),
    );
    const fixture = transport(fetchImpl);

    await expect(
      fixture.client.call("users.list", {}, "run-1"),
    ).rejects.toThrow("deadline exceeded");
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fixture.sleep).not.toHaveBeenCalled();
  });
});

describe("SlackApiTransport user inventory completeness", () => {
  it.each(["repeated-cursor", "later-page-failure"] as const)(
    "rejects the entire inventory after %s instead of returning a partial member list",
    async (failure) => {
      const fetchImpl = vi.fn<typeof fetch>(async (input) => {
        const url = new URL(
          input instanceof Request ? input.url : input.toString(),
        );
        if (url.searchParams.has("cursor") && failure === "later-page-failure")
          return json({ ok: false }, 403);
        return json({
          members: [{ id: "U1", profile: { email: "owner@company.test" } }],
          ok: true,
          "response_metadata": { "next_cursor": "page-2" },
        });
      });
      const { client } = transport(fetchImpl);

      await expect(client.listUsers("run-incomplete")).rejects.toThrow(
        failure === "repeated-cursor"
          ? "Slack users.list repeated a cursor"
          : "Slack users.list HTTP 403",
      );
      expect(fetchImpl).toHaveBeenCalledTimes(2);
    },
  );
});

describe("SlackApiTransport redirect boundary", () => {
  it.each([
    {
      boundary: "read",
      data: {},
      method: "users.profile.get",
      post: false,
      status: 307,
    },
    {
      boundary: "group membership",
      data: { usergroup: "SENG", users: "U123" },
      method: "usergroups.users.update",
      post: true,
      status: 308,
    },
    {
      boundary: "managed profile",
      data: {
        profile: { fields: { "X_TEAM": { value: "Engineering" } } },
        user: "U123",
      },
      method: "users.profile.set",
      post: true,
      status: 307,
    },
    {
      boundary: "real name",
      data: { profile: { "real_name": "Example Person" }, user: "U123" },
      method: "users.profile.set",
      post: true,
      status: 308,
    },
  ])(
    "does not follow a $status redirect at the $boundary boundary",
    async ({ data, method, post, status }) => {
      const fetchImpl = vi.fn<typeof fetch>(async () =>
        Response.redirect("https://unapproved.example/slack", status),
      );
      const fixture = transport(fetchImpl);

      await expect(
        fixture.client.call(method, data, "redirect-run", { post }),
      ).rejects.toThrow(`Slack ${method} HTTP ${String(status)}`);

      expect(fetchImpl).toHaveBeenCalledOnce();
      expect(fetchImpl).toHaveBeenCalledWith(
        expect.stringMatching(/^https:\/\/slack\.com\/api\//u),
        expect.objectContaining({ redirect: "manual" }),
      );
      expect(fixture.sleep).not.toHaveBeenCalled();
    },
  );
});
