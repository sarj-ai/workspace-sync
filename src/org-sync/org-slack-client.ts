import { z } from "zod";

import { logEvent } from "../shared/log-event.ts";
import type { RetryOptions } from "./http.ts";
import type { SlackMember, SlackProfile } from "./model.ts";
import {
  parseSlackWriteResponse,
  SlackApiTransport,
} from "./slack-api-transport.ts";

const SlackFieldValueSchema = z.object({
  alt: z.string().optional(),
  value: z.string().optional(),
});
const SlackProfileSchema = z.object({
  "display_name": z.string().optional(),
  email: z.string().optional(),
  fields: z.record(z.string(), SlackFieldValueSchema).optional(),
  "real_name": z.string().optional(),
  title: z.string().optional(),
});
const AuthTestSchema = z.object({
  ok: z.literal(true),
  "team_id": z.string().min(1),
  "user_id": z.string().min(1),
});
const ProfileFieldSchema = z.object({
  id: z.string().min(1),
  "is_protected": z.boolean().optional(),
  label: z.string().min(1),
  options: z
    .object({
      "is_protected": z.boolean().optional(),
      "is_scim": z.boolean().optional(),
    })
    .optional(),
  "possible_values": z.array(z.string()).nullish(),
  type: z.enum(["options_list", "text", "user"]).or(z.string().min(1)),
});
const TeamProfileSchema = z.object({
  ok: z.literal(true),
  profile: z.object({ fields: z.array(ProfileFieldSchema) }),
});
const UserProfileSchema = z.object({
  ok: z.literal(true),
  profile: SlackProfileSchema,
});
const ProfileSetSchema = z.object({
  ok: z.literal(true),
  profile: SlackProfileSchema.optional(),
});

export type SlackProfileField = z.output<typeof ProfileFieldSchema>;

export interface SlackSnapshot {
  actorUserId: string;
  fields: SlackProfileField[];
  members: SlackMember[];
  scopes: string[];
  teamId: string;
}

export interface IOrgSlackClient {
  getProfile(
    userId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<SlackProfile>;
  listSnapshot(runId: string, deadlineAt?: number): Promise<SlackSnapshot>;
  readProfileSchema?(
    correlationId: string,
    deadlineAt: number,
    expectedTeamId: string,
  ): Promise<Pick<SlackSnapshot, "fields" | "teamId">>;
  setProfile(
    userId: string,
    profile: {
      "display_name"?: string | undefined;
      fields?: Record<string, { alt: string; value: string }> | undefined;
      "real_name"?: string | undefined;
      title?: string | undefined;
    },
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void>;
}

export interface OrgSlackClientOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  token: string;
}

export class OrgSlackClient implements IOrgSlackClient {
  readonly #transport: SlackApiTransport;

  constructor(options: OrgSlackClientOptions) {
    this.#transport = new SlackApiTransport(options);
  }

  async getProfile(
    userId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<SlackProfile> {
    const result = await this.#transport.call(
      "users.profile.get",
      { user: userId },
      correlationId,
      {
        deadlineAt,
      },
    );
    return UserProfileSchema.parse(result.body).profile;
  }

  async readProfileSchema(
    correlationId: string,
    deadlineAt: number,
    expectedTeamId: string,
  ): Promise<Pick<SlackSnapshot, "fields" | "teamId">> {
    const authResponse = await this.#transport.call(
      "auth.test",
      {},
      correlationId,
      {
        deadlineAt,
      },
    );
    const auth = AuthTestSchema.parse(authResponse.body);
    if (auth["team_id"] !== expectedTeamId)
      throw new Error("slack_profile_schema_tenant_mismatch");
    const profileResponse = await this.#transport.call(
      "team.profile.get",
      {},
      correlationId,
      {
        deadlineAt,
      },
    );
    return {
      teamId: auth["team_id"],
      fields: TeamProfileSchema.parse(profileResponse.body).profile.fields,
    };
  }

  async listSnapshot(
    runId: string,
    deadlineAt?: number,
  ): Promise<SlackSnapshot> {
    const authResponse = await this.#transport.call("auth.test", {}, runId, {
      deadlineAt,
    });
    const auth = AuthTestSchema.parse(authResponse.body);
    const scopes = (authResponse.response.headers.get("x-oauth-scopes") ?? "")
      .split(",")
      .map((scope) => scope.trim())
      .filter(Boolean)
      .toSorted();
    const profileResponse = await this.#transport.call(
      "team.profile.get",
      {},
      runId,
      {
        deadlineAt,
      },
    );
    const fields = TeamProfileSchema.parse(profileResponse.body).profile.fields;
    const members = await this.#transport.listUsers(runId, deadlineAt);
    logEvent("org_sync.slack_snapshot", {
      fields: fields.length,
      "run_id": runId,
      users: members.length,
    });
    return {
      actorUserId: auth["user_id"],
      fields,
      members,
      scopes,
      teamId: auth["team_id"],
    };
  }

  async setProfile(
    userId: string,
    profile: {
      "display_name"?: string | undefined;
      fields?: Record<string, { alt: string; value: string }> | undefined;
      "real_name"?: string | undefined;
      title?: string | undefined;
    },
    correlationId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const result = await this.#transport.call(
      "users.profile.set",
      { profile, user: userId },
      correlationId,
      { deadlineAt, post: true },
    );
    parseSlackWriteResponse(ProfileSetSchema, result.body, "users.profile.set");
  }
}
