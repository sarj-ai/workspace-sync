import { logEvent } from "../shared/log-event.ts";
import { exchangeGoogleToken } from "./exchange-google-token.ts";
import type { RetryOptions } from "./http.ts";

const MAX_CACHED_SCOPES = 64;

export interface GoogleDelegatedAuthOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  adminSubject: string;
  operation?: string;
  privateKey: string;
  serviceAccountEmail: string;
}

export interface GoogleDelegatedAuthContract {
  accessToken(
    scope: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<string>;
}

export class GoogleDelegatedAuth implements GoogleDelegatedAuthContract {
  readonly #options: GoogleDelegatedAuthOptions;
  readonly #tokens = new Map<string, { expiresAt: number; value: string }>();
  readonly #pendingTokens = new Map<
    string,
    { deadlineAt: number | undefined; promise: Promise<string> }
  >();

  constructor(options: GoogleDelegatedAuthOptions) {
    this.#options = Object.freeze({ ...options });
  }

  async accessToken(
    scope: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const cached = this.#tokens.get(scope);
    if (cached && cached.expiresAt - 60 > now) return cached.value;
    const pending = this.#pendingTokens.get(scope);
    if (
      pending !== undefined &&
      pending.deadlineAt === deadlineAt &&
      (deadlineAt === undefined || deadlineAt > Date.now())
    )
      return pending.promise;
    const promise = this.#requestToken(scope, runId, deadlineAt);
    this.#pendingTokens.set(scope, { deadlineAt, promise });
    if (this.#pendingTokens.size > MAX_CACHED_SCOPES) {
      const oldest = this.#pendingTokens.keys().next().value;
      if (oldest !== undefined) this.#pendingTokens.delete(oldest);
    }
    try {
      return await promise;
    } finally {
      if (this.#pendingTokens.get(scope)?.promise === promise)
        this.#pendingTokens.delete(scope);
    }
  }

  async #requestToken(
    scope: string,
    runId: string,
    deadlineAt: number | undefined,
  ): Promise<string> {
    const token = await exchangeGoogleToken(
      this.#options,
      scope,
      {
        ...(deadlineAt !== undefined && { deadlineAt }),
        fetchImpl: this.#options.fetchImpl,
        label: "google.oauth.delegated_token",
        random: this.#options.random,
        runId,
        sleep: this.#options.sleep,
      },
      this.#options.adminSubject,
    );
    this.#tokens.set(scope, token);
    if (this.#tokens.size > MAX_CACHED_SCOPES) {
      const oldest = this.#tokens.keys().next().value;
      if (oldest !== undefined) this.#tokens.delete(oldest);
    }
    logEvent(`${this.#options.operation ?? "org_sync"}.google_authenticated`, {
      "run_id": runId,
      scope,
    });
    return token.value;
  }
}
