import { describe, expect, expectTypeOf, it } from "vitest";
import { z } from "zod";

import { PosthogGrantRowCodecSchema } from "../src/workspace-directory/d1-posthog-managed-grant-repository.ts";
import {
  PosthogManagedGrantSchema,
  PosthogUserUuidSchema,
  type PosthogGrantEventFor,
  type PosthogManagedGrant,
  posthogGrantTransition,
} from "../src/workspace-directory/posthog-managed-grant.ts";

const INVITE = "00000000-0000-0000-0000-000000000001";
const USER = "00000000-0000-0000-0000-000000000002";
const IDENTITY = { googleUserId: "222222", email: "product@company.test" };

describe("explicit PostHog ownership and provider evidence", () => {
  it.each(["managed", "retired"] as const)(
    "round trips every constrained relational evidence shape without losing %s history",
    (state) => {
      for (const evidence of [
        { inviteId: INVITE, userUuid: null },
        { inviteId: null, userUuid: USER },
        { inviteId: INVITE, userUuid: USER },
      ]) {
        const row = { ...IDENTITY, ...evidence, state };
        const decoded = PosthogGrantRowCodecSchema.parse(row);
        expect(z.encode(PosthogGrantRowCodecSchema, decoded)).toEqual(row);
        expect("inviteId" in decoded || "userUuid" in decoded).toBe(false);
      }
    },
  );
  it("rejects absent or contradictory evidence and retired-to-managed inference", () => {
    expect(() =>
      PosthogGrantRowCodecSchema.parse({
        ...IDENTITY,
        inviteId: null,
        userUuid: null,
        state: "managed",
      }),
    ).toThrow();
    expect(() =>
      PosthogGrantRowCodecSchema.parse({
        ...IDENTITY,
        inviteId: "bad",
        userUuid: USER,
        state: "retired",
      }),
    ).toThrow();
    expect(() =>
      PosthogManagedGrantSchema.parse({
        ...IDENTITY,
        state: "managed",
        evidence: { kind: "membership", inviteId: INVITE, userUuid: USER },
      }),
    ).toThrow();
    expect(() =>
      PosthogManagedGrantSchema.parse({
        ...IDENTITY,
        evidence: { kind: "membership", userUuid: USER },
      }),
    ).toThrow();
    const grant = PosthogManagedGrantSchema.parse({
      ...IDENTITY,
      state: "retired",
      evidence: { kind: "invitation", inviteId: INVITE },
    });
    expect(() => posthogGrantTransition(grant, { kind: "retire" })).toThrow(
      "posthog_retired_grant_transition",
    );
  });
  it("binds only an owned invitation and retains it through membership retirement", () => {
    const invitation = PosthogManagedGrantSchema.parse({
      ...IDENTITY,
      state: "managed",
      evidence: { kind: "invitation", inviteId: INVITE },
    });
    const bound = posthogGrantTransition(invitation, {
      kind: "bind-member",
      userUuid: PosthogUserUuidSchema.parse(USER),
    });
    expect(bound.evidence).toEqual({
      kind: "accepted-invitation",
      inviteId: INVITE,
      userUuid: USER,
    });
    const retired = posthogGrantTransition(bound, { kind: "retire" });
    expect(retired).toEqual({ ...bound, state: "retired" });
    expect(() =>
      posthogGrantTransition(bound, {
        kind: "bind-member",
        userUuid: PosthogUserUuidSchema.parse(USER),
      }),
    ).toThrow("posthog_grant_already_bound");
  });
});

it("forbids retired grant events and membership rebinding in the type contract", () => {
  expectTypeOf<
    PosthogGrantEventFor<Extract<PosthogManagedGrant, { state: "retired" }>>
  >().toEqualTypeOf<never>();
  expectTypeOf<
    PosthogGrantEventFor<
      Extract<PosthogManagedGrant, { state: "managed" }> & {
        evidence: {
          kind: "membership";
          userUuid: z.output<typeof PosthogUserUuidSchema>;
        };
      }
    >
  >().toEqualTypeOf<{ kind: "retire" }>();
});
