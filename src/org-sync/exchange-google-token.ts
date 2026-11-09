import { importPKCS8, SignJWT } from "jose";
import { z } from "zod";

import { readBoundedText } from "../runtime/read-bounded-text.ts";
import { fetchWithRetry, type RetryOptions } from "./http.ts";

const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const TOKEN_LIFETIME_SECONDS = 3600;
const MAX_TOKEN_RESPONSE_BYTES = 16_384;
const TokenResponseSchema = z.object({
  "access_token": z.string().min(1),
  "expires_in": z.number().int().positive().max(TOKEN_LIFETIME_SECONDS),
});

interface GoogleCredentials {
  readonly privateKey: string;
  readonly serviceAccountEmail: string;
}

/* A missing subject preserves direct service-account access, including Drive. */
export async function exchangeGoogleToken(
  credentials: GoogleCredentials,
  scope: string,
  retry: RetryOptions,
  subject?: string,
): Promise<{ expiresAt: number; value: string }> {
  const now = Math.floor(Date.now() / 1000);
  const key = await importPKCS8(
    credentials.privateKey.replaceAll(String.raw`\n`, "\n"),
    "RS256",
  );
  const jwt = new SignJWT({ scope })
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuer(credentials.serviceAccountEmail)
    .setAudience(TOKEN_ENDPOINT)
    .setIssuedAt(now)
    .setExpirationTime(now + TOKEN_LIFETIME_SECONDS);
  if (subject !== undefined) jwt.setSubject(subject);
  const assertion = await jwt.sign(key);
  const response = await fetchWithRetry(
    TOKEN_ENDPOINT,
    {
      body: new URLSearchParams({
        assertion,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST",
    },
    retry,
  );
  if (!response.ok) {
    void response.body?.cancel().catch(() => undefined);
    throw new Error(
      `Google OAuth token exchange HTTP ${String(response.status)}`,
    );
  }
  const body = await readBoundedText(
    response,
    MAX_TOKEN_RESPONSE_BYTES,
    () => new Error("google_oauth_response_too_large"),
  );
  try {
    const parsed = TokenResponseSchema.parse(JSON.parse(body));
    return {
      expiresAt: now + parsed["expires_in"],
      value: parsed["access_token"],
    };
  } catch {
    throw new Error("google_oauth_invalid_token_response");
  }
}
