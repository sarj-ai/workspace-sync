import { z } from "zod";

import type { IdentityWriteBudget } from "../identity-provisioning/identity-budget-contracts.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";

const CallableSchema = z.function();

export const GoogleIdentityParentBoundarySchema = z.object({
  mode: z.literal("parent"),
  identityBudget: z.object({
    required: z.literal(true),
    reserve: z.custom((value) => CallableSchema.safeParse(value).success),
  }),
});

/** Trusted parent adapter callbacks; not a caller-supplied authorization document. */
export interface GoogleIdentityParentContext<Reviewed> {
  assertFreshPlan(): void;
  assertWriteAuthority(reviewed: Reviewed): Promise<void>;
  captureGoogleAuthority: () => Promise<readonly GoogleDirectoryUser[]>;
  readonly expectedBeforeFingerprint: string;
  readonly identityBudget: Extract<IdentityWriteBudget, { required: true }>;
  readonly mode: "parent";
  verifyPreannouncement: (reviewed: Reviewed) => Promise<void>;
}

export interface GoogleIdentityParentDispatch {
  assertFreshPlan(): void;
  assertWriteAuthority(): Promise<void>;
}
