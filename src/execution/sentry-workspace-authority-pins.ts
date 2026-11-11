import type { z } from "zod";

import {
  type SentryWorkspaceAuthorityBootstrap,
  SentryWorkspaceAuthorityBootstrapSchema,
} from "../workspace-directory/sentry-workspace-client.ts";

export const SentryWorkspaceAuthorityPinsSchema =
  SentryWorkspaceAuthorityBootstrapSchema.pick({
    actor: true,
    organization: true,
    project: true,
    team: true,
  });
export type SentryWorkspaceAuthorityPins = z.output<
  typeof SentryWorkspaceAuthorityPinsSchema
>;

export type SentryWorkspaceAuthorityPinState =
  | {
      readonly kind: "blocked";
      readonly reason: "sentry_authority_pins_invalid";
    }
  | { readonly kind: "off"; readonly reason: "sentry_authority_pins_absent" }
  | { readonly kind: "ready"; readonly pins: SentryWorkspaceAuthorityPins };

/* Pins are parsed lazily so the read-only bootstrap remains available before activation. */
export function sentryWorkspaceAuthorityPinState(
  rawPins: string,
): SentryWorkspaceAuthorityPinState {
  const value = rawPins.trim();
  if (value.length === 0)
    return { kind: "off", reason: "sentry_authority_pins_absent" };
  try {
    return {
      kind: "ready",
      pins: SentryWorkspaceAuthorityPinsSchema.parse(JSON.parse(value)),
    };
  } catch {
    return { kind: "blocked", reason: "sentry_authority_pins_invalid" };
  }
}

export function assertSentryWorkspaceAuthorityPins(
  pins: SentryWorkspaceAuthorityPins,
  evidence: SentryWorkspaceAuthorityBootstrap,
): void {
  const parsedPins = SentryWorkspaceAuthorityPinsSchema.parse(pins);
  const parsedEvidence =
    SentryWorkspaceAuthorityBootstrapSchema.parse(evidence);
  if (
    !sameIdentity(parsedPins.organization, parsedEvidence.organization) ||
    !sameIdentity(parsedPins.project, parsedEvidence.project) ||
    !sameIdentity(parsedPins.team, parsedEvidence.team) ||
    parsedPins.actor.id !== parsedEvidence.actor.id ||
    parsedPins.actor.orgRole !== parsedEvidence.actor.orgRole ||
    parsedPins.actor.role !== parsedEvidence.actor.role ||
    parsedPins.actor.teamRole !== parsedEvidence.actor.teamRole ||
    !sameSet(parsedPins.actor.scopes, parsedEvidence.actor.scopes)
  ) {
    throw new Error("sentry_workspace_authority_pin_mismatch");
  }
}

function sameIdentity(
  left: { readonly id: string; readonly slug: string },
  right: { readonly id: string; readonly slug: string },
): boolean {
  return left.id === right.id && left.slug === right.slug;
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return (
    rightSet.size === right.length && left.every((scope) => rightSet.has(scope))
  );
}
