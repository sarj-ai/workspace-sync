import { describe, expect, it, vi } from "vitest";

import { readBoundedText } from "../src/runtime/read-bounded-text.ts";

describe("bounded HTTP bodies", () => {
  it("decodes multibyte characters across chunk boundaries", async () => {
    const bytes = new TextEncoder().encode("aé🙂");
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
        controller.close();
      },
    });
    await expect(
      readBoundedText({ body: stream }, bytes.length, () => new Error("large")),
    ).resolves.toBe("aé🙂");
  });

  it("cancels a chunked oversized response even when cancellation never settles", async () => {
    const cancel = vi.fn(() => Promise.withResolvers<never>().promise);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(9));
      },
      cancel,
    });
    await expect(
      readBoundedText({ body: stream }, 8, () => new Error("large")),
    ).rejects.toThrow("large");
    expect(cancel).toHaveBeenCalledOnce();
    expect(stream.locked).toBe(false);
  });

  it("rejects non-byte chunks and releases the reader lock", async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue("invalid chunk");
        controller.close();
      },
    });
    await expect(
      readBoundedText({ body: stream }, 100, () => new Error("large")),
    ).rejects.toThrow(TypeError);
    expect(stream.locked).toBe(false);
  });

  it("returns an empty body and releases an ordinary reader", async () => {
    await expect(
      readBoundedText({ body: null }, 0, () => new Error("large")),
    ).resolves.toBe("");
    const response = new Response("exact");
    await expect(
      readBoundedText(response, 5, () => new Error("large")),
    ).resolves.toBe("exact");
    expect(response.body?.locked).toBe(false);
  });
});
