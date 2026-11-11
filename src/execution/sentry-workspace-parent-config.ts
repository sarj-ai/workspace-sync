import type { SentryWorkspaceAuthorityPins } from "./sentry-workspace-authority-pins.ts";
import { sentryWorkspaceAuthorityPinState } from "./sentry-workspace-authority-pins.ts";

export type SentryWorkspaceParentConfig =
  | {
      readonly execution: "blocked";
      readonly reason:
        | "sentry_authority_pins_absent"
        | "sentry_authority_pins_invalid";
    }
  | {
      readonly execution: "disabled";
      readonly reason:
        | "sentry_authority_pins_absent"
        | "sentry_parent_disabled";
    }
  | {
      readonly execution: "managed";
      readonly pins: SentryWorkspaceAuthorityPins;
    };

export function sentryWorkspaceParentConfig(input: {
  readonly enabled: boolean;
  readonly rawAuthorityPins: string;
}): SentryWorkspaceParentConfig {
  const pinState = sentryWorkspaceAuthorityPinState(input.rawAuthorityPins);
  if (!input.enabled) {
    return {
      execution: "disabled",
      reason:
        pinState.kind === "off"
          ? "sentry_authority_pins_absent"
          : "sentry_parent_disabled",
    };
  }
  if (pinState.kind === "off" || pinState.kind === "blocked")
    return { execution: "blocked", reason: pinState.reason };
  return { execution: "managed", pins: pinState.pins };
}
