import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { syncProfiles } from "../examples/sync-profiles.ts";
import { profileSyncFixture } from "./profile-sync-fixture.ts";

describe("SlackProfileSync plan/apply", () => {
  it("previews changes without writing or needing a database", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    expect(plan).toMatchObject({
      status: "audit",
      writes: 0,
      selectedSlackUserId: "UADA",
    });
    expect(plan.planHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(fixture.setProfile).not.toHaveBeenCalled();
  });

  it.each([false, true])(
    "runs the example only after approval: %s",
    async (approved) => {
      const fixture = profileSyncFixture();
      const approve = vi.fn(async () => approved);
      const result = await syncProfiles(fixture.options, approve);
      expect(result.status).toBe(approved ? "success" : "audit");
      expect(approve).toHaveBeenCalledOnce();
      expect(fixture.setProfile).toHaveBeenCalledTimes(approved ? 1 : 0);
    },
  );

  it("applies the approved profile and verifies it with one readback", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.getProfile.mockClear();
    const reserve = vi.fn(async (_id: string) => undefined);
    const result = await fixture.sync.apply(plan, {
      identityBudget: { required: true, reserve },
    });
    expect(result).toMatchObject({
      status: "success",
      writes: 1,
      verified: 1,
      planHash: plan.planHash,
    });
    expect(fixture.getProfile).toHaveBeenCalledTimes(3);
    expect(fixture.setProfile).toHaveBeenCalledOnce();
    expect(reserve).toHaveBeenCalledExactlyOnceWith(fixture.state.user.id);
  });

  it("rejects changed Google data before reserving or writing", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.state.user.organizations = [
      { department: "Engineering", primary: true, title: "Principal Engineer" },
    ];
    const reserve = vi.fn(async (_id: string) => undefined);
    const result = await fixture.sync.apply(plan, {
      identityBudget: { required: true, reserve },
    });
    expect(result).toMatchObject({ status: "blocked", writes: 0, verified: 0 });
    expect(reserve).not.toHaveBeenCalled();
    expect(fixture.setProfile).not.toHaveBeenCalled();
  });

  it("does not overwrite a profile changed just before writing", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.getProfile
      .mockResolvedValueOnce(structuredClone(fixture.state.profile))
      .mockResolvedValueOnce({
        ...fixture.state.profile,
        title: "Edited elsewhere",
      });
    const result = await fixture.sync.apply(plan);
    expect(result).toMatchObject({ status: "failed", writes: 0, verified: 0 });
    expect(result.failed[0]?.error).toContain(
      "changed after the reviewed plan",
    );
    expect(fixture.setProfile).not.toHaveBeenCalled();
  });

  it("accepts a converged profile without writing or consuming a limit", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.getProfile
      .mockResolvedValueOnce(structuredClone(fixture.state.profile))
      .mockResolvedValueOnce({
        ...fixture.state.profile,
        title: "Staff Engineer",
      });
    const reserve = vi.fn(async (_id: string) => undefined);
    const result = await fixture.sync.apply(plan, {
      identityBudget: { required: true, reserve },
    });
    expect(result).toMatchObject({ status: "success", writes: 0, verified: 1 });
    expect(reserve).not.toHaveBeenCalled();
    expect(fixture.setProfile).not.toHaveBeenCalled();
  });

  it("does not repeat a timed-out write when readback confirms it succeeded", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.getProfile.mockClear();
    fixture.setProfile.mockImplementation(async (id, profile) => {
      await fixture.update(id, profile);
      throw new Error("response timed out");
    });
    await expect(fixture.sync.apply(plan)).resolves.toMatchObject({
      status: "success",
      writes: 1,
      verified: 1,
    });
    expect(fixture.setProfile).toHaveBeenCalledOnce();
    expect(fixture.getProfile).toHaveBeenCalledTimes(3);
  });

  it("fails when the provider never applied the change", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.setProfile.mockRejectedValue(new Error("provider refused"));
    const result = await fixture.sync.apply(plan);
    expect(result).toMatchObject({ status: "failed", writes: 0, verified: 0 });
    expect(result.failed[0]?.error).toBe("provider refused");
    expect(fixture.setProfile).toHaveBeenCalledOnce();
  });

  it("fails when a successful response disagrees with provider state", async () => {
    const fixture = profileSyncFixture();
    const plan = await fixture.sync.plan();
    fixture.setProfile.mockResolvedValue(undefined);
    const result = await fixture.sync.apply(plan);
    expect(result).toMatchObject({ status: "failed", verified: 0 });
    expect(result.failed[0]?.error).toContain("read-back mismatch");
  });

  it.each([
    { status: "audit", planHash: "" },
    { status: "failed", planHash: "a".repeat(64) },
  ] as const)(
    "rejects an invalid or failed plan before reading providers: %j",
    async (plan) => {
      const fixture = profileSyncFixture();
      const snapshot = vi.spyOn(fixture.options.slack, "listSnapshot");
      const directory = vi.spyOn(fixture.options.google, "listAllUsers");
      await expect(fixture.sync.apply(plan)).rejects.toBeInstanceOf(z.ZodError);
      expect(snapshot).not.toHaveBeenCalled();
      expect(directory).not.toHaveBeenCalled();
      expect(fixture.setProfile).not.toHaveBeenCalled();
    },
  );
});
