import { describe, expect, it, vi } from "vitest";

import { OrgChannelSlackClient } from "../src/org-sync/org-channel-slack-client.ts";

function memberPage(hasCursor: boolean) {
  return Response.json({
    ok: true,
    members: hasCursor ? ["U2", "U1"] : ["U1"],
    "response_metadata": { "next_cursor": hasCursor ? "" : "next" },
  });
}

function fixture(
  count = 4,
  intercept?: (url: URL) => Promise<null | Response | undefined>,
) {
  const channels = Array.from({ length: count }, (_, index) => ({
    id: `C${String(index)}`,
    name: `channel-${String(index).padStart(2, "0")}`,
    "is_archived": false,
    "is_private": false,
  }));
  const calls: string[] = [];
  const sleep = vi.fn(async (_milliseconds: number) => undefined);
  const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
    if (init?.method === "POST") throw new Error("unexpected provider write");
    const url = new URL(
      input instanceof Request ? input.url : input.toString(),
    );
    const method = url.pathname.split("/").at(-1) ?? "";
    calls.push(
      `${method}:${url.searchParams.get("channel") ?? ""}:${url.searchParams.get("cursor") ?? ""}`,
    );
    const intercepted = await intercept?.(url);
    if (intercepted) return intercepted;
    switch (method) {
      case "auth.test":
        return Response.json({ ok: true, "team_id": "T1", "user_id": "U1" });
      case "users.list":
        return Response.json({ ok: true, members: [] });
      case "conversations.list":
        return Response.json({ ok: true, channels });
      case "conversations.info":
        return Response.json({
          ok: true,
          channel: channels.find(
            ({ id }) => id === url.searchParams.get("channel"),
          ),
        });
      case "conversations.members":
        return memberPage(url.searchParams.has("cursor"));
      default:
        throw new Error("unexpected read");
    }
  });
  const client = new OrgChannelSlackClient({
    token: "xoxp-test",
    fetchImpl,
    sleep,
  });
  return {
    channels,
    client,
    calls,
    sleep,
    fetchImpl,
    names: channels.map(({ name }) => name).toReversed(),
  };
}

describe("bounded channel hydration", () => {
  it("hydrates exactly two channels at once and preserves canonical output under reversed completion", async () => {
    const gates = [
      Promise.withResolvers<undefined>(),
      Promise.withResolvers<undefined>(),
    ];
    const started = Promise.withResolvers<undefined>();
    const secondFinished = Promise.withResolvers<undefined>();
    let active = 0;
    let maximum = 0;
    let firstPair = 0;
    const f = fixture(4, async (url) => {
      if (!url.pathname.endsWith("/conversations.info")) {
        if (
          url.searchParams.get("channel") === "C1" &&
          url.searchParams.has("cursor")
        )
          secondFinished.resolve(undefined);
        return;
      }
      active++;
      maximum = Math.max(maximum, active);
      const index = Number(url.searchParams.get("channel")?.slice(1));
      if (index < 2) {
        if (++firstPair === 2) started.resolve(undefined);
        await gates[index]?.promise;
      }
      active--;
    });
    const pending = f.client.listSnapshot(f.names, "run");
    await started.promise;
    gates[1]?.resolve(undefined);
    await secondFinished.promise;
    expect(
      f.calls.some((call) => call.startsWith("conversations.info:C2")),
    ).toBe(false);
    gates[0]?.resolve(undefined);
    const result = await pending;
    expect(maximum).toBe(2);
    const expected = f.channels.toReversed().map((channel) => ({
      id: channel.id,
      isArchived: false,
      isPrivate: false,
      memberIds: ["U1", "U2"],
      name: channel.name,
    }));
    expect(result.channels).toEqual(expected);
    for (const channel of f.channels) {
      expect(f.calls.indexOf(`conversations.info:${channel.id}:`)).toBeLessThan(
        f.calls.indexOf(`conversations.members:${channel.id}:`),
      );
      expect(
        f.calls.filter((call) =>
          call.startsWith(`conversations.members:${channel.id}:`),
        ),
      ).toEqual([
        `conversations.members:${channel.id}:`,
        `conversations.members:${channel.id}:next`,
      ]);
    }
    const digest = (value: unknown) =>
      crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(JSON.stringify(value)),
      );
    await expect(digest(result.channels)).resolves.toEqual(
      await digest(expected),
    );
  });

  it.each(["invalid-info", "repeated-cursor"] as const)(
    "drains siblings before rejecting %s and never starts another batch",
    async (failure) => {
      const sibling = Promise.withResolvers<undefined>();
      const siblingStarted = Promise.withResolvers<undefined>();
      let siblingFinished = false;
      const f = fixture(4, async (url) => {
        const id = url.searchParams.get("channel");
        if (id === "C1" && url.pathname.endsWith("/conversations.info")) {
          siblingStarted.resolve(undefined);
          await sibling.promise;
          siblingFinished = true;
        }
        if (
          id === "C0" &&
          failure === "invalid-info" &&
          url.pathname.endsWith("/conversations.info")
        )
          return Response.json({ ok: true, channel: { id: "C0" } });
        if (
          id === "C0" &&
          failure === "repeated-cursor" &&
          url.pathname.endsWith("/conversations.members")
        )
          return Response.json({
            ok: true,
            members: ["U1"],
            "response_metadata": { "next_cursor": "same" },
          });
        return null;
      });
      let settled = false;
      const outcome = f.client
        .listSnapshot(f.names, "run")
        .catch((error: unknown) => {
          settled = true;
          return error;
        });
      await siblingStarted.promise;
      await new Promise<void>((resolve) => {
        setTimeout(() => resolve(), 0);
      });
      expect(settled).toBe(false);
      sibling.resolve(undefined);
      await expect(outcome).resolves.toBeInstanceOf(Error);
      expect(siblingFinished).toBe(true);
      expect(
        f.calls.some((call) => call.startsWith("conversations.info:C2")),
      ).toBe(false);
      expect(
        f.calls.filter((call) => call.startsWith("conversations.members:C0:")),
      ).toHaveLength(failure === "invalid-info" ? 0 : 2);
    },
  );

  it("retains the eighty-channel cap before hydration", async () => {
    const f = fixture(81);
    await expect(f.client.listSnapshot(f.names, "run")).rejects.toThrow(
      "80 channel safety limit",
    );
    expect(f.calls.some((call) => call.startsWith("conversations.info:"))).toBe(
      false,
    );
  });

  it.each([false, true])(
    "preserves Retry-After and immutable deadline enforcement (short budget %s)",
    async (short) => {
      let throttled = false;
      const f = fixture(2, async (url) => {
        if (
          !throttled &&
          url.pathname.endsWith("/conversations.info") &&
          url.searchParams.get("channel") === "C0"
        ) {
          throttled = true;
          return new Response("", {
            status: 429,
            headers: { "retry-after": "3" },
          });
        }
        return null;
      });
      const pending = f.client.listSnapshot(
        f.names,
        "run",
        Date.now() + (short ? 2000 : 60_000),
      );
      const outcome = await pending.catch((error: unknown) => error);
      const deadlineFailure = expect.objectContaining({
        message: expect.stringContaining("deadline exceeded before HTTP retry"),
      });
      const complete = expect.objectContaining({ channels: expect.any(Array) });
      expect(outcome).toEqual(short ? deadlineFailure : complete);
      expect(f.sleep.mock.calls).toEqual(short ? [] : [[3000]]);
      expect(
        f.calls.filter((call) => call === "conversations.info:C0:"),
      ).toHaveLength(short ? 1 : 2);
    },
  );
});
