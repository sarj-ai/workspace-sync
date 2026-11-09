import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import {
  TrycompDeactivationResponseSchema,
  type TrycompMember,
  TrycompMemberSchema,
  TrycompPeopleResponseSchema,
} from "./model.ts";

const TRYCOMP_API = "https://api.trycomp.ai";
export const TRYCOMP_PROVIDER_REQUEST_TIMEOUT_MS = 30_000;
type TrycompRequestOperation =
  | "deactivate-member"
  | "invite-member"
  | "list-members"
  | "reactivate-member";

export interface ITrycompPeopleClient {
  deactivate(
    memberId: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void>;
  inviteEmployee(
    email: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void>;
  listMembers(
    requestId: string,
    signal?: AbortSignal,
  ): Promise<TrycompMember[]>;
  reactivate(
    memberId: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void>;
}

export class TrycompPeopleClient implements ITrycompPeopleClient {
  readonly #apiKey: string;
  readonly #fetchImpl: typeof fetch;

  constructor(apiKey: string, fetchImpl: typeof fetch = runtimeFetch) {
    this.#apiKey = apiKey;
    this.#fetchImpl = fetchPort(fetchImpl);
  }

  async deactivate(
    memberId: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const response = await this.#request(
      "deactivate-member",
      `/v1/people/${encodeURIComponent(memberId)}?skipOffboarding=true`,
      requestId,
      {
        method: "DELETE",
      },
      signal,
    );
    const removed = TrycompDeactivationResponseSchema.parse(
      await response.json(),
    );
    if (removed.deletedMember.id !== memberId)
      throw new Error("trycomp_deactivation_identity_mismatch");
  }

  async inviteEmployee(
    email: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const response = await this.#request(
      "invite-member",
      "/v1/people/invite",
      requestId,
      {
        body: JSON.stringify({
          invites: [{ email, roles: ["employee"], sendPortalEmail: false }],
        }),
        headers: { "content-type": "application/json" },
        method: "POST",
      },
      signal,
    );
    await response.body?.cancel();
  }

  async listMembers(
    requestId: string,
    signal?: AbortSignal,
  ): Promise<TrycompMember[]> {
    const response = await this.#request(
      "list-members",
      "/v1/people?includeDeactivated=true",
      requestId,
      {},
      signal,
    );
    const parsed = TrycompPeopleResponseSchema.parse(await response.json());
    if (parsed.count !== parsed.data.length) {
      throw new Error("trycomp_people_count_mismatch");
    }
    return parsed.data;
  }

  async reactivate(
    memberId: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const response = await this.#request(
      "reactivate-member",
      `/v1/people/${encodeURIComponent(memberId)}`,
      requestId,
      {
        body: JSON.stringify({ isActive: true }),
        headers: { "content-type": "application/json" },
        method: "PATCH",
      },
      signal,
    );
    TrycompMemberSchema.parse(await response.json());
  }

  async #request(
    operation: TrycompRequestOperation,
    path: string,
    requestId: string,
    init: RequestInit,
    callerSignal?: AbortSignal,
  ): Promise<Response> {
    if (requestId.trim() === "") throw new Error("trycomp_request_id_missing");
    const headers = new Headers(init.headers);
    headers.set("x-api-key", this.#apiKey);
    headers.set("x-request-id", requestId);
    const timeoutSignal = AbortSignal.timeout(
      TRYCOMP_PROVIDER_REQUEST_TIMEOUT_MS,
    );
    const signal = callerSignal
      ? AbortSignal.any([callerSignal, timeoutSignal])
      : timeoutSignal;
    let response: Response;
    try {
      response = await this.#fetchImpl(`${TRYCOMP_API}${path}`, {
        ...init,
        headers,
        redirect: "manual",
        signal,
      });
    } catch (error) {
      if (timeoutSignal.aborted) {
        throw new Error("trycomp_people_request_timeout", { cause: error });
      }
      if (callerSignal?.aborted) {
        throw new Error("trycomp_people_request_aborted", { cause: error });
      }
      throw new Error("trycomp_people_fetch_failed", { cause: error });
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(
        `trycomp_people_${operation}_http_${String(response.status)}`,
      );
    }
    return response;
  }
}
