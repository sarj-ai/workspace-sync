import { dequal } from "dequal";
import { z } from "zod";

import {
  type LinearProfileAccount,
  LinearProfileAccountSchema,
} from "../access-guard/linear-provider.ts";
import { contentHash } from "../github-access-audit/content-hash.ts";
import {
  type IdentityWriteBudget,
  reserveIdentityWriteBudget,
} from "../identity-provisioning/identity-budget-contracts.ts";
import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { indexNamedActiveGoogleUsers } from "./index-named-active-google-users.ts";

const MAX_ACTIONS = 100;
const MAX_GOOGLE_USERS = 500;
const EmailSchema = z.email().toLowerCase();
const FullNameSchema = z.string().trim().min(1).max(200);
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

export const LinearProfileActionSchema = z.strictObject({
  beforeFullName: FullNameSchema,
  desiredFullName: FullNameSchema,
  email: EmailSchema,
  googleUserId: z.string().min(1),
  linearUserId: z.string().min(1),
  type: z.literal("repair-default-full-name"),
});
export type LinearProfileAction = z.output<typeof LinearProfileActionSchema>;

export const AuditedLinearProfilePlanSchema = z.strictObject({
  actions: z.array(LinearProfileActionSchema),
  authorityUsers: z.array(
    z.strictObject({
      email: EmailSchema,
      googleUserId: z.string().min(1),
      name: FullNameSchema,
    }),
  ),
  planHash: Sha256Schema,
});
export type AuditedLinearProfilePlan = z.output<
  typeof AuditedLinearProfilePlanSchema
>;

export interface ILinearProfileClient {
  getAccount(accountId: string, correlationId: string): Promise<unknown>;
  listProfileAccounts(runId: string): Promise<readonly LinearProfileAccount[]>;
  updateFullName(
    accountId: string,
    fullName: string,
    correlationId: string,
    assertFinalWriteAuthority?: () => Promise<void>,
  ): Promise<LinearProfileAccount>;
}

/*
 * Selects only unambiguous, active, exact-email matches whose Linear full name
 * is still the full email or local-part default. Linear displayName
 * is the user's username/nickname and is deliberately outside this surface.
 */
export function planLinearProfileSync(
  googleUsers: readonly GoogleDirectoryUser[],
  linearAccounts: readonly LinearProfileAccount[],
): Omit<AuditedLinearProfilePlan, "planHash"> {
  if (googleUsers.length > MAX_GOOGLE_USERS)
    throw new LinearProfileBoundError("authority");
  const googleByEmail = indexNamedActiveGoogleUsers(
    googleUsers,
    () => new LinearProfileIdentityError("google"),
  );
  const authorityUsers = new Map(
    googleByEmail.values().map((user) => [user.id, user] as const),
  )
    .values()
    .map((user) => ({
      email: normalizeIdentityEmail(user.primaryEmail),
      googleUserId: user.id,
      name: FullNameSchema.parse(user.name?.fullName),
    }))
    .toArray()
    .toSorted((left, right) => left.email.localeCompare(right.email));
  if (authorityUsers.length === 0)
    throw new LinearProfileIdentityError("authority");
  const seenLinearEmails = new Set<string>();
  const actions: LinearProfileAction[] = [];
  for (const rawAccount of linearAccounts) {
    const account = LinearProfileAccountSchema.parse(rawAccount);
    if (!account.active) continue;
    const email = EmailSchema.parse(account.email);
    if (seenLinearEmails.has(email))
      throw new LinearProfileIdentityError("linear");
    seenLinearEmails.add(email);
    const googleUser = googleByEmail.get(email);
    if (googleUser === undefined) continue;
    const current = account.name?.trim();
    const desired = googleUser.name?.fullName?.trim();
    if (
      !current ||
      !desired ||
      current === desired ||
      !isEmailDefault(current, email)
    )
      continue;
    actions.push({
      beforeFullName: current,
      desiredFullName: desired,
      email,
      googleUserId: googleUser.id,
      linearUserId: account.id,
      type: "repair-default-full-name",
    });
  }
  if (actions.length > MAX_ACTIONS) throw new LinearProfileBoundError("action");
  return {
    actions: LinearProfileActionSchema.array().parse(
      actions.toSorted((left, right) => left.email.localeCompare(right.email)),
    ),
    authorityUsers,
  };
}

export async function auditLinearProfileSync(
  googleUsers: readonly GoogleDirectoryUser[],
  client: ILinearProfileClient,
): Promise<AuditedLinearProfilePlan> {
  const runId = crypto.randomUUID();
  const plan = planLinearProfileSync(
    googleUsers,
    await client.listProfileAccounts(runId),
  );
  return AuditedLinearProfilePlanSchema.parse({
    ...plan,
    planHash: await contentHash({
      actions: plan.actions,
      authorityUsers: plan.authorityUsers,
      policy: "google-full-name-to-linear-default-full-name-v2",
    }),
  });
}

export async function applyLinearProfilePlanAction(
  googleUsers: readonly GoogleDirectoryUser[],
  client: ILinearProfileClient,
  rawAction: LinearProfileAction,
  expectedPlanHash: string,
  identityBudget?: IdentityWriteBudget,
  assertWriteAuthority?: () => Promise<void>,
  assertFinalWriteAuthority?: () => Promise<void>,
): Promise<void> {
  const action = LinearProfileActionSchema.parse(rawAction);
  const current = await auditLinearProfileSync(googleUsers, client);
  if (
    current.planHash !== Sha256Schema.parse(expectedPlanHash) ||
    !current.actions.some((candidate) => sameAction(candidate, action))
  ) {
    throw new LinearProfileDriftError();
  }
  const runId = crypto.randomUUID();
  const before = LinearProfileAccountSchema.parse(
    await client.getAccount(action.linearUserId, runId),
  );
  assertSafeTarget(before, action);
  await reserveIdentityWriteBudget(identityBudget, action.googleUserId);
  if (identityBudget?.required === true) {
    const fresh = LinearProfileAccountSchema.parse(
      await client.getAccount(action.linearUserId, runId),
    );
    assertSafeTarget(fresh, action);
    if (
      fresh.admin !== before.admin ||
      fresh.owner !== before.owner ||
      fresh.app !== before.app
    )
      throw new LinearProfileDriftError();
  }
  await assertWriteAuthority?.();
  const updated = LinearProfileAccountSchema.parse(
    await client.updateFullName(
      action.linearUserId,
      action.desiredFullName,
      runId,
      ...(assertFinalWriteAuthority === undefined
        ? []
        : [assertFinalWriteAuthority]),
    ),
  );
  assertConverged(updated, action);
  const readback = LinearProfileAccountSchema.parse(
    await client.getAccount(action.linearUserId, runId),
  );
  assertConverged(readback, action);
}

export async function isLinearProfileActionConverged(
  client: Pick<ILinearProfileClient, "getAccount">,
  rawAction: LinearProfileAction,
): Promise<boolean> {
  const action = LinearProfileActionSchema.parse(rawAction);
  const account = LinearProfileAccountSchema.parse(
    await client.getAccount(action.linearUserId, crypto.randomUUID()),
  );
  return converged(account, action);
}

function isEmailDefault(name: string, email: string): boolean {
  const normalized = name.trim().toLowerCase();
  return normalized === email || normalized === email.split("@", 1)[0];
}

function assertSafeTarget(
  account: LinearProfileAccount,
  action: LinearProfileAction,
): void {
  if (
    account.id !== action.linearUserId ||
    !account.active ||
    normalizeIdentityEmail(account.email) !== action.email ||
    account.name?.trim() !== action.beforeFullName ||
    !isEmailDefault(action.beforeFullName, action.email)
  ) {
    throw new LinearProfileDriftError();
  }
}

function assertConverged(
  account: LinearProfileAccount,
  action: LinearProfileAction,
): void {
  if (!converged(account, action)) throw new LinearProfileReadbackError();
}

function converged(
  account: LinearProfileAccount,
  action: LinearProfileAction,
): boolean {
  return (
    account.id === action.linearUserId &&
    account.active &&
    normalizeIdentityEmail(account.email) === action.email &&
    account.name?.trim() === action.desiredFullName
  );
}

function sameAction(
  left: LinearProfileAction,
  right: LinearProfileAction,
): boolean {
  return dequal(left, right);
}

export class LinearProfileBoundError extends Error {
  constructor(bound: "action" | "authority", options?: ErrorOptions) {
    super(`linear_profile_${bound}_bound_exceeded`, options);
    this.name = "LinearProfileBoundError";
  }
}

export class LinearProfileIdentityError extends Error {
  constructor(
    source: "authority" | "google" | "linear",
    options?: ErrorOptions,
  ) {
    super(`linear_profile_${source}_identity_ambiguous`, options);
    this.name = "LinearProfileIdentityError";
  }
}

export class LinearProfileDriftError extends Error {
  constructor() {
    super("linear_profile_prewrite_drift");
    this.name = "LinearProfileDriftError";
  }
}

export class LinearProfileReadbackError extends Error {
  constructor() {
    super("linear_profile_readback_failed");
    this.name = "LinearProfileReadbackError";
  }
}
