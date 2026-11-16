import { z } from "zod";

import { runtimeFetch } from "../clients/runtime-fetch.ts";
import { fetchPort } from "../runtime/fetch-port.ts";

type FetchImpl = typeof globalThis.fetch;

export const PosthogIdSchema = z
  .string()
  .regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
export const PosthogOriginSchema = z.enum([
  "https://us.posthog.com",
  "https://eu.posthog.com",
]);
const EmailSchema = z.email().transform((email) => email.toLowerCase());
export const PosthogMemberSchema = z.object({
  id: PosthogIdSchema,
  level: z.number().int().nonnegative(),
  user: z.object({ uuid: PosthogIdSchema, email: EmailSchema }),
});
export const PosthogInviteSchema = z.object({
  id: PosthogIdSchema,
  "target_email": EmailSchema,
  level: z.number().int().nonnegative(),
  "is_expired": z.boolean(),
  "created_by": z.object({ uuid: PosthogIdSchema }),
});
export type PosthogMember = z.output<typeof PosthogMemberSchema>;
export type PosthogInvite = z.output<typeof PosthogInviteSchema>;
export interface PosthogMembershipSnapshot {
  organizationId: string;
  actorUuid: string;
  members: PosthogMember[];
  invites: PosthogInvite[];
}
export interface IPosthogMembershipClient {
  read(): Promise<PosthogMembershipSnapshot>;
  invite(email: string): Promise<PosthogInvite>;
  cancelInvite(inviteId: string): Promise<void>;
  removeMember(userUuid: string): Promise<void>;
}
const MAX_PAGES = 20;

/** A dedicated organization-scoped key needs user:read, organization:read and organization_member:write. */
export class PosthogMembershipClient implements IPosthogMembershipClient {
  readonly #fetch: FetchImpl;
  readonly #origin: string;
  readonly #organizationId: string;
  readonly #actorUuid: string;
  readonly #token: string;

  constructor(options: {
    origin: string;
    organizationId: string;
    actorUuid: string;
    token: string;
    fetchImpl?: FetchImpl;
  }) {
    this.#origin = PosthogOriginSchema.parse(options.origin);
    this.#organizationId = PosthogIdSchema.parse(options.organizationId);
    this.#actorUuid = PosthogIdSchema.parse(options.actorUuid);
    if (!options.token.trim())
      throw new Error("posthog_membership_token_missing");
    this.#token = options.token;
    this.#fetch = fetchPort(options.fetchImpl ?? runtimeFetch);
  }

  async read(): Promise<PosthogMembershipSnapshot> {
    const deadlineAt = Date.now() + 60_000;
    const actorResponse = await this.#request(
      new URL("/api/users/@me/", this.#origin),
      "GET",
      undefined,
      deadlineAt,
    );
    const actor = z
      .object({ uuid: PosthogIdSchema })
      .parse(await actorResponse.json());
    if (actor.uuid !== this.#actorUuid)
      throw new Error("posthog_actor_mismatch");
    const base = `/api/organizations/${this.#organizationId}/`;
    const organizationResponse = await this.#request(
      new URL(base, this.#origin),
      "GET",
      undefined,
      deadlineAt,
    );
    const organization = z
      .object({ id: PosthogIdSchema })
      .parse(await organizationResponse.json());
    if (organization.id !== this.#organizationId)
      throw new Error("posthog_organization_mismatch");
    const [members, invites] = await Promise.all([
      this.#pages(`${base}members/`, PosthogMemberSchema, deadlineAt),
      this.#pages(`${base}invites/`, PosthogInviteSchema, deadlineAt),
    ]);
    const membership = members.find(
      (member) => member.user.uuid === actor.uuid,
    );
    if (
      membership === undefined ||
      (membership.level !== 8 && membership.level !== 15)
    )
      throw new Error("posthog_actor_role_unsupported");
    return {
      organizationId: organization.id,
      actorUuid: actor.uuid,
      members,
      invites,
    };
  }

  async invite(email: string): Promise<PosthogInvite> {
    const target = EmailSchema.parse(email);
    const response = await this.#request(
      new URL(
        `/api/organizations/${this.#organizationId}/invites/`,
        this.#origin,
      ),
      "POST",
      { "target_email": target, level: 1, "send_email": true },
    );
    const invite = PosthogInviteSchema.parse(await response.json());
    if (
      invite["target_email"] !== target ||
      invite.level !== 1 ||
      invite["is_expired"]
    )
      throw new Error("posthog_invitation_acknowledgement_mismatch");
    return invite;
  }

  async cancelInvite(inviteId: string): Promise<void> {
    await this.#request(
      new URL(
        `/api/organizations/${this.#organizationId}/invites/${PosthogIdSchema.parse(inviteId)}/`,
        this.#origin,
      ),
      "DELETE",
    );
  }

  async removeMember(userUuid: string): Promise<void> {
    await this.#request(
      new URL(
        `/api/organizations/${this.#organizationId}/members/${PosthogIdSchema.parse(userUuid)}/`,
        this.#origin,
      ),
      "DELETE",
    );
  }

  async #pages<Schema extends z.ZodType>(
    path: string,
    item: Schema,
    deadlineAt: number,
  ): Promise<z.output<Schema>[]> {
    const pageSchema = z.object({
      results: z.array(item).max(1000),
      next: z.string().nullable(),
    });
    let url: URL | null = new URL(`${path}?limit=100`, this.#origin);
    const seen = new Set<string>();
    const result: z.output<Schema>[] = [];
    while (url !== null) {
      if (
        url.origin !== this.#origin ||
        url.pathname !== path ||
        url.username !== "" ||
        url.password !== "" ||
        url.hash !== ""
      )
        throw new Error("posthog_pagination_authority_mismatch");
      if (seen.size >= MAX_PAGES || seen.has(url.href))
        throw new Error("posthog_pagination_bound");
      seen.add(url.href);
      // eslint-disable-next-line no-await-in-loop -- The provider supplies the next page only after the current response.
      const response = await this.#request(url, "GET", undefined, deadlineAt);
      // eslint-disable-next-line no-await-in-loop -- Validate the current page before following its pagination link.
      const page = pageSchema.parse(await response.json());
      result.push(...page.results);
      url = page.next === null ? null : new URL(page.next, this.#origin);
    }
    return result;
  }

  async #request(
    url: URL,
    method = "GET",
    body?: { "target_email": string; level: number; "send_email": boolean },
    deadlineAt = Date.now() + 30_000,
  ): Promise<Response> {
    if (url.origin !== this.#origin)
      throw new Error("posthog_request_origin_mismatch");
    if (Date.now() >= deadlineAt)
      throw new Error("posthog_read_deadline_exceeded");
    const init: RequestInit = {
      method,
      redirect: "error",
      headers: {
        authorization: `Bearer ${this.#token}`,
        "content-type": "application/json",
      },
      signal: AbortSignal.timeout(Math.min(30_000, deadlineAt - Date.now())),
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const response = await this.#fetch(url.href, init);
    if (!response.ok)
      throw new Error(`posthog_membership_http_${String(response.status)}`);
    return response;
  }
}
