import type { D1Database, D1DatabaseSession } from "@cloudflare/workers-types";
import { z } from "zod";

import { sameJson, sha256Hex } from "../operations/canonical.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import {
  GoogleGithubIdentitySchema,
  GoogleIdentityUserSnapshotSchema,
} from "../org-sync/google-identity-schema.ts";
import { WORKSPACE_DEPLOYMENT_FENCE_KEY } from "../workspace-directory/workspace-deployment-fence-repository.ts";
import {
  type GitHubIdentityAdminAttestationPlan,
  GitHubIdentityAdminAttestationPlanSchema,
} from "./github-identity-admin-attestation.ts";
import {
  type ActiveResourceLease,
  D1ResourceLeaseRepository,
} from "./resource-lease.ts";

const JsonTextSchema = z.string();
const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const AttemptSchema = z.strictObject({
  schemaVersion: z.literal("google-identity-attestation-attempt/v1"),
  plan: GitHubIdentityAdminAttestationPlanSchema,
  deadlineAtMs: z.number().int().nonnegative(),
  recoverAfterMs: z.number().int().nonnegative(),
  attemptedAtMs: z.number().int().nonnegative(),
});
const ObservationSchema = z.strictObject({
  googleUserId: z.string(),
  primaryEmail: z.email(),
  identity: GoogleGithubIdentitySchema.nullable(),
});
const RowSchema = z.object({
  "attempt_id": DigestSchema,
  "plan_hash": DigestSchema,
  "google_user_id": z.string(),
  "snapshot_json": z.string(),
  "attempted_at_ms": z.number().int(),
  kind: z
    .enum(["write-verified", "observed-before", "observed-after"])
    .nullable(),
  "evidence_json": z.string().nullable(),
});
export interface IdentityAttestationAttempt {
  attemptId: string;
  resolution: {
    kind: "observed-after" | "observed-before" | "write-verified";
    observation: z.output<typeof ObservationSchema>;
  } | null;
  snapshot: z.output<typeof AttemptSchema>;
}
const SELECT_ATTEMPT = `SELECT attempt_id, plan_hash, google_user_id, snapshot_json, attempted_at_ms, kind, evidence_json
FROM google_identity_attestation`;

/** Append-only attempted writes remain admission debt until an exact provider observation is durably attached. */
interface ResolveIdentityAttemptInput {
  attemptId: string;
  changeHash?: string;
  kind: "observed-after" | "observed-before" | "write-verified";
  lease: ActiveResourceLease;
  wire: unknown;
}
export interface IGitHubIdentityAttestationAttemptStore {
  begin(
    plan: GitHubIdentityAdminAttestationPlan,
    lease: ActiveResourceLease,
    deadlineAtMs: number,
  ): Promise<string>;
  latest(): Promise<IdentityAttestationAttempt | null>;
  read(attemptId: string): Promise<IdentityAttestationAttempt>;
  resolve(input: ResolveIdentityAttemptInput): Promise<void>;
}
export class GitHubIdentityAttestationAttemptStore implements IGitHubIdentityAttestationAttemptStore {
  readonly #db: D1DatabaseSession;
  readonly #leases: D1ResourceLeaseRepository;
  readonly #now: () => number;
  constructor(database: D1Database, now: () => number = Date.now) {
    this.#db = database.withSession("first-primary");
    this.#leases = new D1ResourceLeaseRepository(database, { clock: now });
    this.#now = now;
  }
  async begin(
    planInput: GitHubIdentityAdminAttestationPlan,
    lease: ActiveResourceLease,
    deadlineAtMs: number,
  ): Promise<string> {
    const plan = GitHubIdentityAdminAttestationPlanSchema.parse(planInput);
    await assertPlanHash(plan);
    const entry = plan.entries[0];
    if (entry?.googlePlan.kind !== "update") throw conflict();
    await this.#leases.assertActive(lease, 90_000);
    const now = this.#now();
    if (
      now >= Date.parse(entry.attestation.attestedAt) + 600_000 ||
      lease.resourceKey !== WORKSPACE_DEPLOYMENT_FENCE_KEY ||
      deadlineAtMs !== lease.expiresAtMs - 30_000 ||
      deadlineAtMs <= now
    )
      throw conflict();
    const attemptId = await sha256Hex({
      kind: "google-identity-attestation-attempt/v1",
      planHash: plan.planHash,
    });
    const snapshot = AttemptSchema.parse({
      schemaVersion: "google-identity-attestation-attempt/v1",
      plan,
      deadlineAtMs,
      recoverAfterMs: lease.expiresAtMs,
      attemptedAtMs: now,
    });
    const result = await this.#db
      .prepare(`INSERT INTO google_identity_attestation (attempt_id,plan_hash,google_user_id,snapshot_json,attempted_at_ms)
SELECT ?1,?2,?3,?4,?5 WHERE EXISTS (SELECT 1 FROM automation_singleton_lease WHERE lease_key=?6 AND owner_id=?7 AND generation=?8 AND expires_at_ms>=?9)
AND NOT EXISTS (SELECT 1 FROM google_identity_attestation WHERE kind IS NULL)`)
      .bind(
        attemptId,
        plan.planHash,
        entry.googlePlan.user.id,
        JSON.stringify(snapshot),
        now,
        lease.resourceKey,
        lease.ownerId,
        lease.generation,
        now + 90_000,
      )
      .run();
    if (result.meta.changes !== 1) throw conflict();
    return attemptId;
  }
  async latest(): Promise<IdentityAttestationAttempt | null> {
    return this.#parse(
      await this.#db
        .prepare(`${SELECT_ATTEMPT} ORDER BY rowid DESC LIMIT 1`)
        .first(),
    );
  }
  async read(attemptId: string): Promise<IdentityAttestationAttempt> {
    const found = await this.#parse(
      await this.#db
        .prepare(`${SELECT_ATTEMPT} WHERE attempt_id=?1`)
        .bind(DigestSchema.parse(attemptId))
        .first(),
    );
    if (found === null) throw conflict();
    return found;
  }
  async resolve(input: ResolveIdentityAttemptInput): Promise<void> {
    if (input.lease.resourceKey !== WORKSPACE_DEPLOYMENT_FENCE_KEY)
      throw conflict();
    const attempt = await this.read(input.attemptId);
    if (attempt.resolution !== null) throw conflict();
    await this.#leases.assertActive(input.lease, 30_000);
    const observation = observeIdentityAttempt(attempt, input.wire);
    const category = classifyIdentityAttempt(attempt, observation);
    if (category !== (input.kind === "observed-before" ? "before" : "after"))
      throw conflict();
    if (
      input.kind !== "write-verified" &&
      this.#now() < attempt.snapshot.recoverAfterMs
    )
      throw conflict();
    const changeHash =
      input.changeHash === undefined
        ? null
        : DigestSchema.parse(input.changeHash);
    if ((input.kind === "write-verified") !== (changeHash === null))
      throw conflict();
    const result = await this.#db
      .prepare(`UPDATE google_identity_attestation SET kind=?2, evidence_json=?3, change_hash=?4, resolved_at_ms=?5
WHERE attempt_id=?1 AND kind IS NULL
AND EXISTS(SELECT 1 FROM automation_singleton_lease WHERE lease_key=?6 AND owner_id=?7 AND generation=?8 AND expires_at_ms>=?9)`)
      .bind(
        input.attemptId,
        input.kind,
        JSON.stringify(observation),
        changeHash,
        this.#now(),
        input.lease.resourceKey,
        input.lease.ownerId,
        input.lease.generation,
        this.#now() + 30_000,
      )
      .run();
    if (result.meta.changes !== 1) throw conflict();
  }
  async #parse(raw: unknown): Promise<IdentityAttestationAttempt | null> {
    if (raw === null) return null;
    const row = RowSchema.parse(raw);
    const snapshot = AttemptSchema.parse(JSON.parse(row["snapshot_json"]));
    await assertPlanHash(snapshot.plan);
    const expectedId = await sha256Hex({
      kind: "google-identity-attestation-attempt/v1",
      planHash: snapshot.plan.planHash,
    });
    if (
      expectedId !== row["attempt_id"] ||
      snapshot.plan.planHash !== row["plan_hash"] ||
      snapshot.plan.entries[0]?.googlePlan.user.id !== row["google_user_id"] ||
      snapshot.attemptedAtMs !== row["attempted_at_ms"] ||
      snapshot.deadlineAtMs + 30_000 !== snapshot.recoverAfterMs
    )
      throw conflict();
    const resolution =
      row.kind === null
        ? null
        : {
            kind: row.kind,
            observation: ObservationSchema.parse(
              JSON.parse(JsonTextSchema.parse(row["evidence_json"])),
            ),
          };
    const attempt = { attemptId: row["attempt_id"], snapshot, resolution };
    if (
      resolution !== null &&
      classifyIdentityAttempt(attempt, resolution.observation) !==
        (resolution.kind === "observed-before" ? "before" : "after")
    )
      throw conflict();
    return attempt;
  }
}
export function observeIdentityAttempt(
  attempt: IdentityAttestationAttempt,
  wire: unknown,
): z.output<typeof ObservationSchema> {
  const current = GoogleIdentityUserSnapshotSchema.strip().parse(wire);
  const expected = attempt.snapshot.plan.entries[0];
  if (
    current.id !== expected?.googlePlan.user.id ||
    current.primaryEmail !== expected.googlePlan.user.primaryEmail
  )
    throw conflict();
  const raw = current.customSchemas?.SarjIdentity;
  let identity: null | z.output<typeof GoogleGithubIdentitySchema> = null;
  if (
    raw !== undefined &&
    (raw.githubLogin !== undefined || raw.githubUserId !== undefined)
  )
    identity = GoogleGithubIdentitySchema.parse({
      githubLogin: raw.githubLogin,
      githubUserId: raw.githubUserId,
    });
  return ObservationSchema.parse({
    googleUserId: current.id,
    primaryEmail: current.primaryEmail,
    identity,
  });
}
export function classifyIdentityAttempt(
  attempt: IdentityAttestationAttempt,
  observation: z.output<typeof ObservationSchema>,
): "after" | "before" | "drifted" {
  const entry = attempt.snapshot.plan.entries[0];
  if (
    entry?.googlePlan.kind !== "update" ||
    observation.googleUserId !== entry.googlePlan.user.id ||
    observation.primaryEmail !== entry.googlePlan.user.primaryEmail
  )
    throw conflict();
  if (
    sameJson(
      JsonValueSchema.parse(observation.identity),
      JsonValueSchema.parse(entry.googlePlan.desired),
    )
  )
    return "after";
  if (
    sameJson(
      JsonValueSchema.parse(observation.identity),
      JsonValueSchema.parse(entry.googlePlan.current),
    )
  )
    return "before";
  return "drifted";
}
async function assertPlanHash(
  plan: GitHubIdentityAdminAttestationPlan,
): Promise<void> {
  const { planHash, ...body } = plan;
  if ((await sha256Hex(JsonValueSchema.parse(body))) !== planHash)
    throw conflict();
}
function conflict() {
  return new Error("google_identity_attempt_conflict");
}
