import { describe, expect, it } from "vitest";

import { TrycompSafetyReadModelSchema } from "../src/trycomp/safety.ts";

const boundary = TrycompSafetyReadModelSchema.shape.latestActions.element;
const identity = {
  actionIndex: 0,
  actionType: "invite",
  authorityGroupId: null,
  deactivationAuthority: null,
  email: "member@company.test",
  googleUserId: "123",
  memberId: null,
  runId: "d8f58015-dcf4-435d-8d3b-3cb5b84b39ee",
};

describe("Trycomp action state boundary", () => {
  it.each([
    { state: "planned", memberId: null, errorCode: null },
    { state: "attempted", memberId: null, errorCode: null },
    { state: "provider_accepted", memberId: null, errorCode: null },
    { state: "verified", memberId: "verified-member", errorCode: null },
    {
      state: "ambiguous",
      memberId: null,
      errorCode: "provider_acknowledgement_lost",
    },
  ])("accepts required evidence for $state", (state) => {
    expect(boundary.parse({ ...identity, ...state })).toEqual({
      ...identity,
      ...state,
    });
  });

  it.each([
    { state: "planned", errorCode: "stale" },
    { state: "attempted", errorCode: "stale" },
    { state: "provider_accepted", errorCode: "stale" },
    { state: "verified", errorCode: null },
    { state: "verified", memberId: "", errorCode: null },
    { state: "verified", memberId: "member", errorCode: "contradiction" },
    { state: "ambiguous", errorCode: null },
    { state: "ambiguous", errorCode: "" },
    { state: "unknown", errorCode: null },
  ])("rejects contradictory action evidence: %j", (state) => {
    expect(boundary.safeParse({ ...identity, ...state }).success).toBe(false);
  });
  it.each([
    "planned",
    "attempted",
    "provider_accepted",
    "verified",
    "ambiguous",
  ])(
    "never admits a member mutation without its immutable member ID in %s",
    (state) => {
      for (const actionType of ["reactivate", "deactivate"]) {
        expect(
          boundary.safeParse({
            ...identity,
            actionType,
            state,
            errorCode: state === "ambiguous" ? "unknown" : null,
          }).success,
        ).toBe(false);
      }
    },
  );
});
