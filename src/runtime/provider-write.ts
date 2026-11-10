/** A provider response is only an acknowledgement. Readback must establish the effect. */
export type ProviderWriteOutcome =
  | { readonly kind: "acknowledged" }
  | { readonly kind: "uncertain"; readonly error: Error };

// Execute once; a thrown request is never evidence that its effect did not happen.
export async function providerWrite(
  request: () => Promise<void>,
): Promise<ProviderWriteOutcome> {
  try {
    await request();
    return { kind: "acknowledged" };
  } catch (error) {
    return {
      kind: "uncertain",
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}
