import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import {
  type ProviderReadinessContext,
  ProviderReadinessError,
} from "../provider-readiness.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import { logEvent } from "../shared/log-event.ts";
import type { DownstreamAccount } from "./model.ts";
import type { AccessEnforcementProvider } from "./provider.ts";

const LINEAR_GRAPHQL_URL = "https://api.linear.app/graphql";
const LINEAR_REQUEST_TIMEOUT_MS = 15_000;
export const LinearProfileAccountSchema = z.object({
  active: z.boolean(),
  admin: z.boolean().optional(),
  app: z.boolean().optional(),
  displayName: z.string().optional(),
  email: z.string().trim().toLowerCase().pipe(z.email()),
  id: z.string().min(1),
  name: z.string().optional(),
  owner: z.boolean().optional(),
});
export type LinearProfileAccount = z.output<typeof LinearProfileAccountSchema>;
export interface LinearProfileProviderContract extends AccessEnforcementProvider {
  listProfileAccounts(runId: string): Promise<readonly LinearProfileAccount[]>;
  updateFullName(
    accountId: string,
    fullName: string,
    correlationId: string,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<LinearProfileAccount>;
}
const UsersPageSchema = z.object({
  data: z.object({
    users: z.object({
      nodes: z.array(LinearProfileAccountSchema),
      pageInfo: z.object({
        endCursor: z.string().nullable(),
        hasNextPage: z.boolean(),
      }),
    }),
  }),
});
const UserResponseSchema = z.object({
  data: z.object({ user: LinearProfileAccountSchema }),
});
const SuspendResponseSchema = z.object({
  data: z.object({ userSuspend: z.object({ success: z.literal(true) }) }),
});
const UpdateProfileResponseSchema = z.object({
  data: z.object({
    userUpdate: z.object({
      success: z.literal(true),
      user: LinearProfileAccountSchema,
    }),
  }),
});
const GraphqlErrorSchema = z.object({
  errors: z.array(z.object({ message: z.string() })),
});
const OrganizationSchema = z.object({
  id: z.uuid(),
  urlKey: z.string().min(1),
});
const OrganizationResponseSchema = z.object({
  data: z.object({ organization: OrganizationSchema }),
});

export class LinearAccessProvider implements LinearProfileProviderContract {
  readonly name = "linear";
  readonly #apiKey: string;
  readonly #fetchImpl: FetchImpl;
  readonly #tenant: {
    expectedOrganizationId: null | string;
    expectedOrganizationUrlKey: string;
  };

  constructor(
    apiKey: string,
    tenant: {
      expectedOrganizationId: null | string;
      expectedOrganizationUrlKey: string;
    },
    fetchImpl: FetchImpl = runtimeFetch,
  ) {
    this.#apiKey = apiKey;
    this.#tenant = tenant;
    this.#fetchImpl = fetchPort(fetchImpl);
  }

  async getAccount(accountId: string, correlationId: string) {
    await this.#assertTenant(correlationId);
    const raw = await this.#graphql(
      `query AccessGuardUser($id: String!) {
        user(id: $id) { id name displayName email active admin owner app }
      }`,
      { id: accountId },
    );
    return UserResponseSchema.parse(raw).data.user;
  }

  async listAccounts(runId: string): Promise<readonly DownstreamAccount[]> {
    return this.listProfileAccounts(runId);
  }

  async listProfileAccounts(
    runId: string,
  ): Promise<readonly LinearProfileAccount[]> {
    await this.#assertTenant(runId);
    const users: LinearProfileAccount[] = [];
    let after: null | string = null;
    for (let page = 1; page <= 20; page++) {
      // eslint-disable-next-line no-await-in-loop -- Linear pagination is cursor-ordered and bounded.
      const raw = await this.#graphql(
        `query AccessGuardUsers($after: String) {
          users(first: 100, after: $after) {
            nodes { id name displayName email active admin owner app }
            pageInfo { hasNextPage endCursor }
          }
        }`,
        { after },
      );
      const parsed = UsersPageSchema.parse(raw);
      users.push(...parsed.data.users.nodes);
      if (!parsed.data.users.pageInfo.hasNextPage) return users;
      const next = parsed.data.users.pageInfo.endCursor;
      if (!next || next === after)
        throw new Error("linear_users_invalid_page_cursor");
      after = next;
    }
    throw new Error("linear_users_page_limit_exceeded");
  }

  async updateFullName(
    accountId: string,
    fullName: string,
    correlationId: string,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<LinearProfileAccount> {
    await this.#assertTenant(correlationId);
    await assertFinalWriteAuthority?.();
    const raw = await this.#graphql(
      `mutation WorkspaceDirectoryLinearProfileUpdate(
        $id: String!
        $input: UserUpdateInput!
      ) {
        userUpdate(id: $id, input: $input) {
          success
          user { id name displayName email active admin owner app }
        }
      }`,
      { id: accountId, input: { name: fullName.trim() } },
    );
    return UpdateProfileResponseSchema.parse(raw).data.userUpdate.user;
  }

  async suspendAccount(
    accountId: string,
    correlationId: string,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<void> {
    await this.#assertTenant(correlationId);
    await assertFinalWriteAuthority?.();
    const raw = await this.#graphql(
      `mutation AccessGuardSuspendUser($id: String!) {
        userSuspend(id: $id) { success }
      }`,
      { id: accountId },
    );
    SuspendResponseSchema.parse(raw);
  }

  async #assertTenant(runId: string): Promise<void> {
    const raw = await this.#graphql(
      "query AccessGuardOrganization { organization { id urlKey } }",
      {},
    );
    const organization =
      OrganizationResponseSchema.parse(raw).data.organization;
    logEvent("access_guard.linear_tenant_observed", {
      "organization_id": organization.id,
      "run_id": runId,
      "url_key": organization.urlKey,
    });
    const readinessContext = (
      errorCode: ProviderReadinessContext["error_code"],
    ): ProviderReadinessContext => ({
      "error_code": errorCode,
      kind: "linear_tenant" as const,
      "observed_organization_id": organization.id,
      "observed_url_key": organization.urlKey,
    });
    if (organization.urlKey !== this.#tenant.expectedOrganizationUrlKey) {
      throw new ProviderReadinessError(
        readinessContext("linear_organization_url_key_mismatch"),
      );
    }
    if (!this.#tenant.expectedOrganizationId) {
      throw new ProviderReadinessError(
        readinessContext("linear_organization_id_unpinned"),
      );
    }
    if (organization.id !== this.#tenant.expectedOrganizationId) {
      throw new ProviderReadinessError(
        readinessContext("linear_organization_id_mismatch"),
      );
    }
  }

  async #graphql(query: string, variables: Record<string, unknown>) {
    const response = await this.#fetchImpl(LINEAR_GRAPHQL_URL, {
      body: JSON.stringify({ query, variables }),
      headers: {
        authorization: this.#apiKey,
        "content-type": "application/json",
      },
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(LINEAR_REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      response.body?.cancel().catch(() => null);
      throw new Error(`linear_http_${String(response.status)}`);
    }
    const raw: unknown = await response.json();
    const graphqlError = GraphqlErrorSchema.safeParse(raw);
    if (graphqlError.success) {
      throw new Error(
        `linear_graphql_${graphqlError.data.errors[0]?.message.slice(0, 100) ?? "error"}`,
      );
    }
    return raw;
  }
}

type FetchImpl = typeof fetch;
