/* Call injected fetch implementations without a class receiver or credential redirects. */
export function fetchPort(implementation: typeof fetch): typeof fetch {
  return (input, init) =>
    implementation(input, { ...init, redirect: "manual" });
}
