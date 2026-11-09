import { describe, expect, it, vi } from "vitest";

import { GoogleDirectoryUserIdSchema } from "../src/identity-lifecycle/contracts.ts";
import { GoogleDirectoryLifecycleWebhookHandler } from "../src/identity-lifecycle/webhook-handler.ts";

const headers = {
  "x-goog-channel-id": "channel-000000000001",
  "x-goog-channel-token": "a-synthetic-channel-token-with-32-bytes",
  "x-goog-message-number": "42",
  "x-goog-resource-id": "opaque-resource-id",
  "x-goog-resource-state": "update",
  "x-goog-resource-uri":
    "https://admin.googleapis.com/admin/directory/v1/users",
};

function fixture(authenticated = true) {
  const finish = vi.fn().mockResolvedValue(true);
  const send = vi.fn().mockResolvedValue(undefined);
  const claim = vi.fn().mockResolvedValue({
    kind: "acquired",
    lease: {
      channelId: headers["x-goog-channel-id"],
      generation: 1,
      messageNumber: "42",
      ownerId: "test-owner",
    },
  });
  const resolveImmutableGoogleUserId = vi
    .fn()
    .mockResolvedValue(
      GoogleDirectoryUserIdSchema.parse("100000000000000000020"),
    );
  const handler = new GoogleDirectoryLifecycleWebhookHandler({
    authenticator: {
      authenticate: async () =>
        authenticated
          ? { kind: "authenticated" }
          : { kind: "rejected", reason: "unknown" },
    },
    receipts: { claim, finish },
    queue: { send },
    subjectResolver: { resolveImmutableGoogleUserId },
  });
  return { handler, finish, send, claim, resolveImmutableGoogleUserId };
}

describe("Google notification consumption", () => {
  it("authenticates before claiming or resolving a notification", async () => {
    const current = fixture(false);
    const response = await current.handler.handle(
      new Request("https://example.com/events", {
        method: "POST",
        headers,
        body: "{}",
      }),
    );
    expect(response.status).toBe(401);
    expect(current.claim).not.toHaveBeenCalled();
    expect(current.resolveImmutableGoogleUserId).not.toHaveBeenCalled();
    expect(current.send).not.toHaveBeenCalled();
  });

  it("cancels a chunked oversized body before buffering the rest", async () => {
    const current = fixture();
    const cancel = vi.fn();
    let chunks = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          chunks += 1;
          controller.enqueue(new Uint8Array(2048));
        },
        cancel,
      },
      { highWaterMark: 0 },
    );
    const init = { method: "POST", headers, body, duplex: "half" };
    const response = await current.handler.handle(
      new Request("https://example.com/events", init),
    );
    expect(response.status).toBe(400);
    expect(chunks).toBe(3);
    expect(cancel).toHaveBeenCalledOnce();
    expect(current.send).not.toHaveBeenCalled();
    expect(current.finish).toHaveBeenCalledWith(
      expect.anything(),
      "ignored",
      expect.any(Number),
    );
  });

  it("enqueues only the validated immutable subject and deduplicates a replay", async () => {
    const current = fixture();
    const body = JSON.stringify({
      etag: "test-etag",
      id: "100000000000000000020",
      kind: "admin#directory#user",
      primaryEmail: "person@example.com",
    });
    const response = await current.handler.handle(
      new Request("https://example.com/events", {
        method: "POST",
        headers,
        body,
      }),
    );
    expect(response.status).toBe(202);
    expect(current.send).toHaveBeenCalledWith(
      expect.objectContaining({
        googleUserId: "100000000000000000020",
        type: "identity.refresh-google-directory-user",
      }),
    );
    current.claim.mockResolvedValueOnce({
      kind: "duplicate",
      outcome: "enqueued",
    });
    await current.handler.handle(
      new Request("https://example.com/events", {
        method: "POST",
        headers,
        body,
      }),
    );
    expect(current.send).toHaveBeenCalledOnce();
  });
});
