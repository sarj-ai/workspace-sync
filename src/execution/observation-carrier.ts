import { sameJson } from "../operations/canonical.ts";
import { OperationContractError } from "../operations/registry.ts";
import { JsonValueSchema, type ManagedChange } from "../operations/schemas.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";

export const IDENTITY_TRANSITION_EXCLUSION = "excluded-until-parent-adapter/v1";

export function workspaceObservationCarrier(
  plan: WorkspaceDirectoryPlan,
): ManagedChange {
  if (
    plan.branches[5].schemaPlan.kind !== "not-selected" ||
    plan.branches[5].githubIdentitySeed.kind !== "disabled"
  )
    throw new OperationContractError(
      "workspace-directory.google-identity-schema",
    );
  const slice = observationSlice();
  // Zod preserves explicitly-present optional properties whose value is undefined.
  // They are valid in the in-memory Workspace plan, but the signed operation
  // envelope is JSON-only. Normalize the already-validated plan exactly as the
  // HTTP boundary does before binding it into the observation carrier.
  const serializedPlan = JSON.stringify(plan);
  const jsonPlan = JsonValueSchema.parse(JSON.parse(serializedPlan));
  return {
    actionId: "workspace-directory.fanout",
    before: slice,
    after: slice,
    details: JsonValueSchema.parse({ kind: "fanout", plan: jsonPlan }),
    display:
      "Observe Workspace reconciliation; Google identity transitions remain excluded.",
    reason:
      "Preserve the signed audit snapshot without selecting an unsupported identity write.",
    kind: "invoke",
    resource: { id: "observation", type: "workspace-directory" },
    risk: "low",
  };
}

export function readWorkspaceObservation(
  excluded: boolean,
  change: ManagedChange,
) {
  if (!excluded || !isWorkspaceObservation(change))
    throw new OperationContractError(
      "workspace-directory.google-identity-schema",
    );
  return observationSlice();
}

export function isWorkspaceObservation(change: ManagedChange): boolean {
  const slice = observationSlice();
  return (
    change.actionId === "workspace-directory.fanout" &&
    change.resource.id === "observation" &&
    change.resource.type === "workspace-directory" &&
    change.kind === "invoke" &&
    change.risk === "low" &&
    sameJson(change.before, slice) &&
    sameJson(change.after, slice)
  );
}

function observationSlice() {
  return JsonValueSchema.parse({
    kind: "observation",
    identityTransitions: IDENTITY_TRANSITION_EXCLUSION,
  });
}
