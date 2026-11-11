import {
  type GoogleGithubIdentitySeedPlan,
  managedSlice as currentGoogleGithubIdentitySlice,
  desiredManagedSlice as desiredGoogleGithubIdentitySlice,
} from "../identity-sync/google-github-identity-seed-service.ts";
import { JsonValueSchema, type JsonValue } from "../operations/schemas.ts";
import type { WorkspaceDirectoryPlan } from "./contracts.ts";
import { slackGroupsChannelsManagedSlice } from "./slack-groups-channels-managed-slice.ts";
type SlackGroupsChannelsPlan = WorkspaceDirectoryPlan["branches"][2];
type SlackProfilesPlan = WorkspaceDirectoryPlan["branches"][0];
const IDENTITY_SCHEMA_NOT_SELECTED =
  "workspace_directory_identity_schema_not_selected";

export function slackGroupsChannelsBeforeSlice(
  branch: SlackGroupsChannelsPlan,
): JsonValue {
  return JsonValueSchema.parse(
    slackGroupsChannelsManagedSlice(branch, "pending"),
  );
}

export function slackGroupsChannelsAfterSlice(
  branch: SlackGroupsChannelsPlan,
): JsonValue {
  return JsonValueSchema.parse(
    slackGroupsChannelsManagedSlice(branch, "verified"),
  );
}

export function slackProfilesBeforeSlice(branch: SlackProfilesPlan): JsonValue {
  return JsonValueSchema.parse(
    branch.changes.map(({ before, slackUserId }) => ({
      fields: before,
      slackUserId,
    })),
  );
}

export function slackProfilesAfterSlice(branch: SlackProfilesPlan): JsonValue {
  return JsonValueSchema.parse(
    branch.changes.map(({ after, slackUserId }) => ({
      fields: after,
      slackUserId,
    })),
  );
}

export function fanoutSlice(
  plan: WorkspaceDirectoryPlan,
  side: "after" | "before",
): ReturnType<typeof JsonValueSchema.parse> {
  const schemaPlan = plan.branches[5].schemaPlan;
  if (schemaPlan.kind === "not-selected") {
    throw new Error(IDENTITY_SCHEMA_NOT_SELECTED);
  }
  const identitySeed = plan.branches[5].githubIdentitySeed;
  const githubIdentities =
    identitySeed.kind !== "managed"
      ? []
      : githubIdentitySlice(identitySeed.userPlans, side);
  return JsonValueSchema.parse({
    githubIdentities,
    identitySchema: schemaPlan[side],
  });
}

function githubIdentitySlice(
  plans: Extract<
    GoogleGithubIdentitySeedPlan,
    { kind: "managed" }
  >["userPlans"],
  side: "after" | "before",
): JsonValue {
  const changes = plans.filter((plan) => plan.kind === "update");
  return side === "before"
    ? currentGoogleGithubIdentitySlice(changes)
    : desiredGoogleGithubIdentitySlice(changes);
}
