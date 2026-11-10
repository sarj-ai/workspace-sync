import type { D1Database } from "@cloudflare/workers-types";
import { z } from "zod";

import { GitHubIdentityAttestationAttemptStore } from "../identity-sync/github-identity-attestation-attempt-store.ts";
import { GoogleGithubIdentitySchema } from "../org-sync/google-identity-schema.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { GoogleDirectoryUserIdSchema } from "./contracts.ts";

const SnapshotSchema = z.strictObject({
  googleUserId: GoogleDirectoryUserIdSchema,
  github: GoogleGithubIdentitySchema.nullable(),
  isAdmin: z.boolean().nullable(),
  isDelegatedAdmin: z.boolean().nullable(),
});
const RowSchema = z.strictObject({
  "observed_at_ms": z.number().int().nonnegative(),
  "snapshot_json": z.string(),
});
const DeletionTimeSchema = z.iso.datetime({ offset: true });
const ObservationTimeSchema = z.number().int().nonnegative();
const AttestationRowSchema = z.strictObject({
  "attempt_id": z.string().regex(/^[a-f0-9]{64}$/u),
  "resolved_at_ms": z.number().int().nonnegative().nullable(),
});

export interface IGoogleDirectoryIdentityHistory {
  remember(user: GoogleDirectoryUser, observedAtMs: number): Promise<void>;
  restoreDeleted(user: GoogleDirectoryUser): Promise<GoogleDirectoryUser>;
}

/** Retains only Google-attested identity links that Google's deleted-user API omits. */
export class D1GoogleDirectoryIdentityHistory implements IGoogleDirectoryIdentityHistory {
  readonly #db: D1Database;

  constructor(db: D1Database) {
    this.#db = db;
  }

  async remember(
    user: GoogleDirectoryUser,
    observedAtMs: number,
  ): Promise<void> {
    if (user.deletionTime !== undefined) return;
    const identity = user.customSchemas?.SarjIdentity;
    const github = GoogleGithubIdentitySchema.safeParse({
      githubLogin: identity?.githubLogin,
      githubUserId: identity?.githubUserId,
    });
    const snapshot = SnapshotSchema.parse({
      googleUserId: user.id,
      github: github.success ? github.data : null,
      isAdmin: user.isAdmin ?? null,
      isDelegatedAdmin: user.isDelegatedAdmin ?? null,
    });
    const observed = ObservationTimeSchema.parse(observedAtMs);
    await this.#db
      .withSession("first-primary")
      .prepare(`INSERT INTO google_directory_identity_history
      (google_user_id, observed_at_ms, snapshot_json) VALUES (?1, ?2, ?3)
      ON CONFLICT (google_user_id) DO UPDATE SET
        observed_at_ms = excluded.observed_at_ms, snapshot_json = excluded.snapshot_json
      WHERE excluded.observed_at_ms > google_directory_identity_history.observed_at_ms`)
      .bind(user.id, observed, JSON.stringify(snapshot))
      .run();
  }

  async restoreDeleted(
    user: GoogleDirectoryUser,
  ): Promise<GoogleDirectoryUser> {
    if (user.deletionTime === undefined) return user;
    const deletedAt = Date.parse(DeletionTimeSchema.parse(user.deletionTime));
    const id = GoogleDirectoryUserIdSchema.parse(user.id);
    const raw = await this.#db
      .withSession("first-primary")
      .prepare(`SELECT observed_at_ms, snapshot_json
      FROM google_directory_identity_history WHERE google_user_id = ?1`)
      .bind(id)
      .first();
    if (raw === null) return this.#restoreAttestedIdentity(user, deletedAt);
    const row = RowSchema.parse(raw);
    if (row["observed_at_ms"] > deletedAt) return user;
    const saved = SnapshotSchema.parse(JSON.parse(row["snapshot_json"]));
    if (saved.googleUserId !== id)
      throw new Error("google_identity_history_id_mismatch");
    const current = user.customSchemas?.SarjIdentity;
    const missing =
      current?.githubLogin === undefined && current?.githubUserId === undefined;
    return {
      ...user,
      ...(user.isAdmin === undefined &&
        saved.isAdmin !== null && { isAdmin: saved.isAdmin }),
      ...(user.isDelegatedAdmin === undefined &&
        saved.isDelegatedAdmin !== null && {
          isDelegatedAdmin: saved.isDelegatedAdmin,
        }),
      ...(missing &&
        saved.github !== null && {
          customSchemas: {
            ...user.customSchemas,
            SarjIdentity: { ...current, ...saved.github },
          },
        }),
    };
  }

  async #restoreAttestedIdentity(
    user: GoogleDirectoryUser,
    deletedAt: number,
  ): Promise<GoogleDirectoryUser> {
    const current = user.customSchemas?.SarjIdentity;
    if (
      current?.githubLogin !== undefined ||
      current?.githubUserId !== undefined
    )
      return user;
    const raw = await this.#db
      .withSession("first-primary")
      .prepare(`SELECT attempt_id, resolved_at_ms
      FROM google_identity_attestation
      WHERE google_user_id = ?1
      ORDER BY attempted_at_ms DESC, attempt_id DESC LIMIT 1`)
      .bind(user.id)
      .first();
    if (raw === null) return user;
    const row = AttestationRowSchema.parse(raw);
    if (row["resolved_at_ms"] === null || row["resolved_at_ms"] > deletedAt)
      return user;
    // The attempt store verifies immutable row IDs, plan hashes and exact provider readback.
    const attempt = await new GitHubIdentityAttestationAttemptStore(
      this.#db,
    ).read(row["attempt_id"]);
    const entry = attempt.snapshot.plan.entries[0];
    if (
      attempt.snapshot.attemptedAtMs > deletedAt ||
      row["resolved_at_ms"] < attempt.snapshot.attemptedAtMs ||
      attempt.resolution === null ||
      attempt.resolution.kind === "observed-before" ||
      attempt.snapshot.plan.entries.length !== 1 ||
      entry?.googlePlan.kind !== "update" ||
      entry.googlePlan.user.id !== user.id ||
      entry.googlePlan.user.primaryEmail.toLowerCase() !==
        user.primaryEmail.toLowerCase() ||
      entry.attestation.subject.kind !== "google-user-id" ||
      entry.attestation.subject.googleUserId !== user.id
    )
      return user;
    // Identity receipts contain no administrator classification; preserve its uncertainty.
    return {
      ...user,
      customSchemas: {
        ...user.customSchemas,
        SarjIdentity: { ...current, ...entry.target },
      },
    };
  }
}

export function assertRetainedGoogleGitHubOwnership(
  user: GoogleDirectoryUser,
  activeUsers: readonly GoogleDirectoryUser[],
): void {
  const identity = GoogleGithubIdentitySchema.safeParse(
    user.customSchemas?.SarjIdentity,
  );
  if (!identity.success) return;
  const emails = new Set(
    [
      user.primaryEmail,
      ...(user.aliases ?? []),
      ...(user.nonEditableAliases ?? []),
    ].map((email) => email.toLowerCase()),
  );
  if (
    activeUsers.some(
      (other) =>
        other.id !== user.id &&
        (other.customSchemas?.SarjIdentity?.githubUserId ===
          identity.data.githubUserId ||
          other.customSchemas?.SarjIdentity?.githubLogin?.toLowerCase() ===
            identity.data.githubLogin ||
          [
            other.primaryEmail,
            ...(other.aliases ?? []),
            ...(other.nonEditableAliases ?? []),
          ].some((email) => emails.has(email.toLowerCase()))),
    )
  )
    throw new Error("github_deprovision_google_identity_conflict");
}
