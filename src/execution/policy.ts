import { z } from "zod";

import { AccessGuardSettingsSchema } from "./access-guard-settings-schema.ts";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const RevisionSchema = z.string().regex(/^[a-f0-9]{40}$/u);
const EpochSchema = z.number().int().nonnegative();
export const CanaryResolutionPinsSchema = z.strictObject({
  tickId: DigestSchema,
  intentId: DigestSchema,
  workflowId: DigestSchema,
  paramsDigest: DigestSchema,
  planHash: DigestSchema,
  workerVersionId: z.uuid(),
  workerRevision: RevisionSchema,
  workflowVersionId: z.uuid(),
  evidenceId: z.string().regex(/^github-actions:[0-9]+:[0-9]+$/u),
  scheduledAtMs: EpochSchema,
  attemptedAtMs: EpochSchema,
  expiresAtMs: EpochSchema,
  reservedAtMs: EpochSchema,
  revision: z.number().int().nonnegative(),
  googleUserId: z.string().regex(/^[1-9][0-9]{5,30}$/u),
  slackUserId: z.string().regex(/^U[A-Z0-9]+$/u),
  slackUserGroupId: z.string().regex(/^S[A-Z0-9]+$/u),
});
export type CanaryResolutionPins = z.output<typeof CanaryResolutionPinsSchema>;
export const WorkspaceExecutionPolicySchema = z.strictObject({
  notificationStatusUrl: z.url(),
  sentry: z.strictObject({
    organizationSlug: z.string().regex(/^[a-z0-9][a-z0-9_-]*$/u),
    authorityGroupEmail: z.email(),
    applyLeaseKey: z.string().min(1),
  }),
  expectedNoTeamAssignmentIdentities: z.array(z.email()),
  accessGuard: AccessGuardSettingsSchema,
  ledger: z.strictObject({
    channelId: z.string().regex(/^C[A-Z0-9]+$/u),
    channelName: z.string().regex(/^[a-z0-9_-]+$/u),
  }),
  legacyCanaryResolution: CanaryResolutionPinsSchema,
});
