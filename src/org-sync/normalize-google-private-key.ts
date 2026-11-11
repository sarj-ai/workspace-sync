// Secrets can contain escaped newlines when supplied through an environment binding.
export function normalizeGooglePrivateKey(value: string): string {
  return value.replaceAll(String.raw`\n`, "\n");
}
