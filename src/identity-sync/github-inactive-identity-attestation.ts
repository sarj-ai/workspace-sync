import { z } from "zod";

import {
  GoogleUserIdSchema,
  PrimaryEmailSchema,
} from "../catalog/identity-authority.ts";
import { protectedIdentityBlocker } from "../identity-provisioning/protected-identity-blocker.ts";
import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import { orgSyncSettings } from "../org-sync/config.ts";
import {
  GoogleGithubIdentitySchema,
  GoogleIdentityUserSnapshotSchema,
  type SarjIdentitySchemaService,
} from "../org-sync/google-identity-schema.ts";
import {
  type GitHubIdentityAdminAttestationPlan,
  GitHubIdentityAdminAttestationPlanSchema,
  type GitHubIdentityResolver,
  type GoogleIdentityAttestationDirectory,
} from "./github-identity-admin-attestation.ts";
import type { GoogleIdentityMaintenanceFence } from "./google-identity-maintenance-fence-error.ts";

const LifecycleSchema = z.strictObject({
  suspended: z.boolean(),
  archived: z.boolean(),
});
export const InactiveGitHubAttestationRequestSchema = z.strictObject({
  schemaVersion: z.literal("github-inactive-identity-attestation/v1"),
  googleUserId: GoogleUserIdSchema,
  primaryEmail: PrimaryEmailSchema,
  lifecycle: LifecycleSchema.refine(
    ({ suspended, archived }) => suspended || archived,
  ),
  githubIdentity: GoogleGithubIdentitySchema,
});
const UserSchema = GoogleIdentityUserSnapshotSchema.extend({
  suspended: z.boolean(),
  archived: z.boolean(),
  isAdmin: z.boolean(),
  isDelegatedAdmin: z.boolean(),
  aliases: z.array(z.email()).optional(),
  nonEditableAliases: z.array(z.email()).optional(),
}).strip();
export const InactiveGitHubAttestationPlanSchema = z.strictObject({
  request: InactiveGitHubAttestationRequestSchema,
  before: UserSchema,
  attestation: GitHubIdentityAdminAttestationPlanSchema,
});
type Request = z.output<typeof InactiveGitHubAttestationRequestSchema>;
type Plan = z.output<typeof InactiveGitHubAttestationPlanSchema>;
type User = z.output<typeof UserSchema>;
interface Context {
  actorId: string;
  attestedAt: string;
}
const GitHubAccountSchema = z.object({
  id: z.number().int().positive(),
  login: z.string(),
});
interface Ports {
  github: GitHubIdentityResolver;
  google: Omit<GoogleIdentityAttestationDirectory, "listIdentityUsers"> & {
    listIdentityUsers(deadlineAtMs?: number): Promise<readonly unknown[]>;
  };
  maintenanceFence: GoogleIdentityMaintenanceFence<GitHubIdentityAdminAttestationPlan>;
  now?: () => number;
  schema: Pick<SarjIdentitySchemaService, "plan">;
}

export interface IInactiveGitHubIdentityAttestationService {
  apply(raw: unknown): Promise<void>;
  plan(raw: unknown, context: Context): Promise<Plan>;
  read(raw: unknown): Promise<User>;
}
export class InactiveGitHubIdentityAttestationService implements IInactiveGitHubIdentityAttestationService {
  readonly #ports: Ports;
  constructor(ports: Ports) {
    this.#ports = ports;
  }

  async plan(raw: unknown, context: Context): Promise<Plan> {
    const request = InactiveGitHubAttestationRequestSchema.parse(raw);
    const before = await this.#capture(request);
    return this.#plan(request, before, context);
  }

  async read(raw: unknown): Promise<User> {
    return this.#capture(InactiveGitHubAttestationRequestSchema.parse(raw));
  }

  async apply(raw: unknown): Promise<void> {
    const reviewed = InactiveGitHubAttestationPlanSchema.parse(raw);
    const entry = reviewed.attestation.entries[0];
    if (entry === undefined) throw conflict();
    const context = {
      actorId: entry.attestation.attestedBy,
      attestedAt: entry.attestation.attestedAt,
    };
    const expected = await this.#plan(
      reviewed.request,
      reviewed.before,
      context,
    );
    if (
      !sameJson(
        JsonValueSchema.parse(expected),
        JsonValueSchema.parse(reviewed),
      )
    )
      throw conflict();
    const expiresAt = Date.parse(context.attestedAt) + 600_000;
    this.#fresh(expiresAt);
    await this.#ports.maintenanceFence.withFence(async (guard) => {
      const deadline = Math.min(expiresAt, guard.deadlineAtMs);
      const current = await this.#capture(reviewed.request, deadline);
      if (sameIdentity(current, reviewed.request)) return;
      assertBefore(current, reviewed.before);
      await guard.assertWriteAuthority(expiresAt);
      let attemptId: string | undefined;
      try {
        await this.#ports.google.updateUser({
          userId: reviewed.request.googleUserId,
          expectedEtag: reviewed.before.etag,
          identity: reviewed.request.githubIdentity,
          preservedCustomSchemas: reviewed.before.customSchemas ?? {},
          maintenanceGuard: {
            deadlineAtMs: deadline,
            assertWriteAuthority: () => guard.assertWriteAuthority(expiresAt),
            beforeDispatch: async () => {
              assertBefore(
                await this.#capture(reviewed.request, deadline),
                reviewed.before,
              );
              await guard.assertWriteAuthority(expiresAt);
              this.#fresh(deadline);
              attemptId = await guard.beginAttempt(reviewed.attestation);
              this.#fresh(deadline);
            },
          },
        });
      } catch {
        // Preserve uncertainty until exact readback; never retry this PUT.
      }
      // A transport error never authorizes another PUT; exact readback may resolve the durable attempt.
      if (attemptId === undefined) throw conflict();
      const after = await this.#capture(reviewed.request, deadline);
      if (!sameIdentity(after, reviewed.request)) throw conflict();
      const expectedSchemas = afterSchemas(reviewed.before, reviewed.request);
      if (
        !sameJson(
          JsonValueSchema.parse(after.customSchemas ?? {}),
          JsonValueSchema.parse(expectedSchemas),
        )
      )
        throw conflict();
      await guard.assertWriteAuthority(expiresAt);
      this.#fresh(deadline);
      await guard.resolveAttempt(attemptId, after);
    });
  }

  async #plan(request: Request, before: User, context: Context): Promise<Plan> {
    assertEligible(before, request);
    const user = {
      id: before.id,
      primaryEmail: before.primaryEmail,
      etag: before.etag,
    };
    const googlePlan = sameIdentity(before, request)
      ? { kind: "unchanged" as const, user, identity: request.githubIdentity }
      : {
          kind: "update" as const,
          user,
          current: null,
          desired: request.githubIdentity,
        };
    const body = {
      schemaVersion: "github-identity-admin-attestation-plan/v1" as const,
      entries: [
        {
          attestation: {
            githubLogin: request.githubIdentity.githubLogin,
            subject: {
              kind: "google-user-id" as const,
              googleUserId: request.googleUserId,
            },
            attestedBy: context.actorId,
            attestedAt: context.attestedAt,
          },
          target: request.githubIdentity,
          googlePlan,
        },
      ],
    };
    return InactiveGitHubAttestationPlanSchema.parse({
      request,
      before,
      attestation: {
        ...body,
        planHash: await sha256Hex(JsonValueSchema.parse(body)),
      },
    });
  }

  async #capture(
    request: Request,
    deadlineAtMs = (this.#ports.now ?? Date.now)() + 60_000,
  ): Promise<User> {
    const deadline = Math.min(
      deadlineAtMs,
      (this.#ports.now ?? Date.now)() + 60_000,
    );
    this.#fresh(deadline);
    const schema = await this.#ports.schema.plan();
    if (schema.kind !== "unchanged") throw conflict();
    this.#fresh(deadline);
    const inventory = z
      .array(GoogleIdentityUserSnapshotSchema.strip())
      .parse(await this.#ports.google.listIdentityUsers(deadline));
    if (
      inventory.filter((user) => user.deletionTime === undefined).length <
        orgSyncSettings().minimumGoogleParticipants ||
      new Set(inventory.map(({ id }) => id)).size !== inventory.length ||
      new Set(inventory.map(({ primaryEmail }) => primaryEmail.toLowerCase()))
        .size !== inventory.length ||
      orgSyncSettings().expectedRootGoogleUserIds.some(
        (id) =>
          !inventory.some(
            (user) =>
              user.id === id &&
              !user.suspended &&
              !user.archived &&
              user.deletionTime === undefined,
          ),
      )
    )
      throw conflict();
    for (const user of inventory) {
      const identity = observedIdentity(user);
      if (
        user.id !== request.googleUserId &&
        identity !== null &&
        (identity.githubUserId === request.githubIdentity.githubUserId ||
          identity.githubLogin === request.githubIdentity.githubLogin)
      )
        throw conflict();
    }
    const listed = inventory.filter(
      ({ id, primaryEmail }) =>
        id === request.googleUserId ||
        primaryEmail.toLowerCase() === request.primaryEmail,
    );
    if (
      listed.length !== 1 ||
      listed[0]?.id !== request.googleUserId ||
      listed[0].primaryEmail.toLowerCase() !== request.primaryEmail
    )
      throw conflict();
    this.#fresh(deadline);
    const github = GitHubAccountSchema.parse(
      await this.#ports.github.resolveUser(request.githubIdentity.githubLogin),
    );
    if (
      String(github.id) !== request.githubIdentity.githubUserId ||
      github.login.toLowerCase() !== request.githubIdentity.githubLogin
    )
      throw conflict();
    this.#fresh(deadline);
    const exactUser = UserSchema.parse(
      await this.#ports.google.readUserById(request.googleUserId, deadline),
    );
    assertEligible(exactUser, request);
    this.#fresh(deadline);
    return exactUser;
  }

  #fresh(deadline: number): void {
    if ((this.#ports.now ?? Date.now)() >= deadline) throw conflict();
  }
}

function assertEligible(user: User, request: Request): void {
  if (
    user.id !== request.googleUserId ||
    user.primaryEmail.toLowerCase() !== request.primaryEmail ||
    user.suspended !== request.lifecycle.suspended ||
    user.archived !== request.lifecycle.archived ||
    user.deletionTime !== undefined ||
    orgSyncSettings().protectedDepartedGoogleUserIds.includes(user.id) ||
    protectedIdentityBlocker({
      ...user,
      googleUserId: user.id,
      aliases: [...(user.aliases ?? []), ...(user.nonEditableAliases ?? [])],
    }) !== undefined
  )
    throw conflict();
  const current = observedIdentity(user);
  if (
    current !== null &&
    !sameJson(
      JsonValueSchema.parse(current),
      JsonValueSchema.parse(request.githubIdentity),
    )
  )
    throw conflict();
}
function observedIdentity(user: Pick<User, "customSchemas">) {
  const current = user.customSchemas?.SarjIdentity;
  if (current?.githubUserId === undefined && current?.githubLogin === undefined)
    return null;
  return GoogleGithubIdentitySchema.parse({
    githubUserId: current.githubUserId,
    githubLogin: current.githubLogin,
  });
}
function sameIdentity(user: User, request: Request) {
  return sameJson(
    JsonValueSchema.parse(observedIdentity(user)),
    JsonValueSchema.parse(request.githubIdentity),
  );
}
function assertBefore(current: User, before: User) {
  if (!sameJson(JsonValueSchema.parse(current), JsonValueSchema.parse(before)))
    throw conflict();
}
export function afterSchemas(
  user: Pick<User, "customSchemas">,
  request: Request,
) {
  return {
    ...user.customSchemas,
    SarjIdentity: {
      ...user.customSchemas?.SarjIdentity,
      ...request.githubIdentity,
    },
  };
}
export function inactiveIdentitySlice(user: User) {
  return {
    googleUserId: user.id,
    primaryEmail: user.primaryEmail,
    lifecycle: { suspended: user.suspended, archived: user.archived },
    customSchemas: user.customSchemas ?? {},
  };
}
function conflict(): Error {
  return new Error("github_inactive_identity_attestation_conflict");
}
