import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import {
  GitHubOrganizationActorSchema,
  GitHubOrganizationMembershipReader,
} from "../github/organization-membership-reader.ts";
import { fetchPort } from "../runtime/fetch-port.ts";
import {
  type DownstreamAccount,
  DownstreamAccountSchema,
  type GitHubAccessRead,
  GitHubAccessReadSchema,
} from "./model.ts";
import type {
  EmailAccessAuditProvider,
  GitHubAccessAuditProvider,
} from "./provider.ts";

const ATTIO_MEMBERS_API = "https://api.attio.com/v2/workspace_members";
const ATTIO_SELF_API = "https://api.attio.com/v2/self";
const ATTIO_REQUIRED_SCOPE = "user_management:read";
const GITHUB_API = "https://api.github.com";
const PAGERDUTY_API = "https://api.pagerduty.com";
const MAX_PAGES = 20;
const AttioMembersSchema = z.object({
  data: z.array(
    z.object({
      "email_address": z.string().trim().toLowerCase().pipe(z.email()),
      "first_name": z.string().optional(),
      id: z.object({
        "workspace_id": z.uuid(),
        "workspace_member_id": z.string().min(1),
      }),
      "last_name": z.string().optional(),
    }),
  ),
});
const AttioTokenMetadataSchema = z.discriminatedUnion("active", [
  z.object({ active: z.literal(false) }),
  z.object({
    active: z.literal(true),
    scope: z.string(),
    "token_type": z.literal("Bearer"),
    "workspace_id": z.uuid(),
  }),
]);
const PagerDutyUsersPageSchema = z.object({
  limit: z.number().int().positive(),
  more: z.boolean(),
  offset: z.number().int().nonnegative(),
  users: z.array(
    z.object({
      email: z.email(),
      id: z.string().min(1),
      name: z.string().optional(),
    }),
  ),
});

export class AttioAccessProvider implements EmailAccessAuditProvider {
  readonly #apiKey: string;
  readonly #expectedWorkspaceId: null | string;
  readonly #fetchImpl: FetchImpl;
  readonly name = "attio";

  constructor(
    apiKey: string,
    expectedWorkspaceId: null | string,
    fetchImpl: FetchImpl = runtimeFetch,
  ) {
    this.#apiKey = apiKey;
    this.#expectedWorkspaceId = expectedWorkspaceId;
    this.#fetchImpl = fetchPort(fetchImpl);
  }

  async listAccounts(_runId: string): Promise<readonly DownstreamAccount[]> {
    if (!this.#apiKey)
      throw new Error("attio_user_management_read_token_missing");
    if (!this.#expectedWorkspaceId)
      throw new Error("attio_workspace_id_pin_missing");
    const headers = { authorization: `Bearer ${this.#apiKey}` };
    const metadataResponse = await this.#fetchImpl(ATTIO_SELF_API, {
      headers,
      method: "GET",
      redirect: "manual",
    });
    if (!metadataResponse.ok) {
      throw new Error(
        `attio_token_metadata_http_${String(metadataResponse.status)}`,
      );
    }
    const metadata = AttioTokenMetadataSchema.parse(
      await metadataResponse.json(),
    );
    if (!metadata.active) throw new Error("attio_token_inactive");
    if (metadata["workspace_id"] !== this.#expectedWorkspaceId) {
      throw new Error("attio_workspace_id_mismatch");
    }
    const scopes = metadata.scope.trim().split(/\s+/u);
    if (scopes.length !== 1 || scopes[0] !== ATTIO_REQUIRED_SCOPE) {
      throw new Error("attio_token_scope_mismatch");
    }
    const response = await this.#fetchImpl(ATTIO_MEMBERS_API, {
      headers,
      method: "GET",
      redirect: "manual",
    });
    if (!response.ok)
      throw new Error(
        `attio_workspace_members_http_${String(response.status)}`,
      );
    const parsed = AttioMembersSchema.parse(await response.json());
    if (
      parsed.data.some(
        (member) => member.id["workspace_id"] !== this.#expectedWorkspaceId,
      )
    ) {
      throw new Error("attio_workspace_id_mismatch");
    }
    return parsed.data.map((member) => {
      const displayName = [member["first_name"], member["last_name"]]
        .filter(Boolean)
        .join(" ")
        .trim();
      return {
        active: true,
        ...(displayName && { displayName }),
        email: member["email_address"],
        id: member.id["workspace_member_id"],
      };
    });
  }
}

export class GitHubOrganizationAccessProvider implements GitHubAccessAuditProvider {
  readonly #fetchImpl: FetchImpl;
  readonly #organization: string;
  readonly #token: string;
  readonly name = "github";

  constructor(
    token: string,
    organization: string,
    fetchImpl: FetchImpl = runtimeFetch,
  ) {
    this.#fetchImpl = fetchPort(fetchImpl);
    this.#organization = organization;
    this.#token = token;
  }

  async readAccess(_runId: string): Promise<GitHubAccessRead> {
    if (!this.#token)
      throw new Error("github_organization_members_read_token_missing");
    const reader = new GitHubOrganizationMembershipReader(
      this.#organization,
      this.#paginate.bind(this),
      async (login) => {
        const response = await this.#fetchImpl(
          `${GITHUB_API}/users/${encodeURIComponent(login)}`,
          {
            headers: {
              accept: "application/vnd.github+json",
              authorization: `Bearer ${this.#token}`,
              "user-agent": "workspace-sync-access-guard",
              "x-github-api-version": "2022-11-28",
            },
            method: "GET",
            redirect: "manual",
            signal: AbortSignal.timeout(15_000),
          },
        );
        if (!response.ok)
          throw new Error(
            `github_organization_access_http_${String(response.status)}`,
          );
        return GitHubOrganizationActorSchema.parse(await response.json());
      },
    );
    const captured = await reader.capture();
    return GitHubAccessReadSchema.parse({
      accounts: [
        ...captured.members.map((actor) => ({
          access: "member" as const,
          active: true as const,
          id: String(actor.id),
          login: actor.login,
          type: actor.type,
        })),
        ...captured.outsideCollaborators.map((actor) => ({
          access: "outside_collaborator" as const,
          active: true as const,
          id: String(actor.id),
          login: actor.login,
          type: actor.type,
        })),
      ],
      invitations: captured.invitations.map((invitation) => ({
        email: invitation.email,
        id: invitation.id,
        login: invitation.login,
        invitee: invitation.invitee
          ? {
              id: String(invitation.invitee.id),
              login: invitation.invitee.login,
              type: invitation.invitee.type,
            }
          : invitation.invitee,
        role: invitation.role,
      })),
    });
  }

  async #paginate<T>(path: string, itemSchema: z.ZodType<T>): Promise<T[]> {
    const items: T[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const separator = path.includes("?") ? "&" : "?";
      // eslint-disable-next-line no-await-in-loop -- GitHub REST pagination is ordered and bounded.
      const response = await this.#fetchImpl(
        `${GITHUB_API}${path}${separator}per_page=100&page=${String(page)}`,
        {
          headers: {
            accept: "application/vnd.github+json",
            authorization: `Bearer ${this.#token}`,
            "user-agent": "workspace-sync-access-guard",
            "x-github-api-version": "2022-11-28",
          },
          method: "GET",
          redirect: "manual",
        },
      );
      if (!response.ok) {
        throw new Error(
          `github_organization_access_http_${String(response.status)}`,
        );
      }
      // eslint-disable-next-line no-await-in-loop -- Each page is validated before advancing.
      const parsed = z.array(itemSchema).parse(await response.json());
      items.push(...parsed);
      if (parsed.length < 100) return items;
    }
    throw new Error("github_organization_access_page_limit_exceeded");
  }
}

export class PagerDutyAccessProvider implements EmailAccessAuditProvider {
  readonly #fetchImpl: FetchImpl;
  readonly #token: string;
  readonly name = "pagerduty";

  constructor(token: string, fetchImpl: FetchImpl = runtimeFetch) {
    this.#fetchImpl = fetchPort(fetchImpl);
    this.#token = token;
  }

  async listAccounts(_runId: string): Promise<readonly DownstreamAccount[]> {
    const accounts: unknown[] = [];
    let offset = 0;
    for (let page = 1; page <= MAX_PAGES; page++) {
      const query = new URLSearchParams({
        limit: "100",
        offset: String(offset),
      });
      // eslint-disable-next-line no-await-in-loop -- PagerDuty pagination is offset-ordered and bounded.
      const response = await this.#fetchImpl(
        `${PAGERDUTY_API}/users?${query.toString()}`,
        {
          headers: {
            accept: "application/vnd.pagerduty+json;version=2",
            authorization: `Token token=${this.#token}`,
          },
          redirect: "manual",
        },
      );
      if (!response.ok)
        throw new Error(`pagerduty_users_http_${String(response.status)}`);
      // eslint-disable-next-line no-await-in-loop -- Each page must be parsed before selecting the next offset.
      const parsed = PagerDutyUsersPageSchema.parse(await response.json());
      accounts.push(
        ...parsed.users.map((user) => ({
          active: true,
          displayName: user.name,
          email: user.email,
          id: user.id,
        })),
      );
      if (!parsed.more) return DownstreamAccountSchema.array().parse(accounts);
      const nextOffset = parsed.offset + parsed.limit;
      if (nextOffset <= offset) throw new Error("pagerduty_users_invalid_page");
      offset = nextOffset;
    }
    throw new Error("pagerduty_users_page_limit_exceeded");
  }
}

type FetchImpl = typeof fetch;
