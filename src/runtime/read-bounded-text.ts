/* Read a decoded HTTP body without buffering an unbounded provider response. */
export async function readBoundedText(
  input: { readonly body: ReadableStream<Uint8Array> | null },
  maxBytes: number,
  failure: () => Error,
): Promise<string> {
  if (input.body === null) return "";
  const reader = input.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let bytes = 0;
  try {
    for (;;) {
      // eslint-disable-next-line no-await-in-loop -- Each read advances the same response stream.
      const chunk: ReadableStreamReadResult<unknown> = await reader.read();
      if (chunk.done) break;
      if (!(chunk.value instanceof Uint8Array))
        throw new TypeError("response_chunk_invalid");
      bytes += chunk.value.byteLength;
      if (bytes > maxBytes) {
        void reader.cancel().catch(() => undefined);
        throw failure();
      }
      chunks.push(decoder.decode(chunk.value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    reader.releaseLock();
  }
}
