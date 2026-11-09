import { describe, expect, it, vi } from "vitest";

import {
  SARJ_IDENTITY_SCHEMA_FIELDS,
  SarjIdentitySchemaService,
} from "../src/org-sync/google-identity-schema.ts";

function fixture(converged = false) {
  let current = {
    displayName: "SarjIdentity",
    etag: "schema-etag-1",
    fields: converged
      ? [...SARJ_IDENTITY_SCHEMA_FIELDS]
      : [SARJ_IDENTITY_SCHEMA_FIELDS[0]],
    schemaId: "schema-original",
    schemaName: "SarjIdentity",
  };
  const gateway = {
    addFields: vi.fn(async () => {
      current = { ...current, fields: [...SARJ_IDENTITY_SCHEMA_FIELDS] };
    }),
    createSchema: vi.fn(async () => undefined),
    readSchema: vi.fn(async () => current),
  };
  return {
    converge() {
      current = { ...current, fields: [...SARJ_IDENTITY_SCHEMA_FIELDS] };
    },
    gateway,
    replace() {
      current = {
        ...current,
        fields: [...SARJ_IDENTITY_SCHEMA_FIELDS],
        schemaId: "schema-replacement",
      };
    },
    service: new SarjIdentitySchemaService(gateway),
  };
}

describe("Reviewed Google schema immutable identity", () => {
  it.each([false, true])(
    "accepts convergence of the original schema without writing (already converged: %s)",
    async (converged) => {
      const f = fixture(converged);
      const plan = await f.service.plan();
      f.converge();
      await expect(f.service.applyPlan(plan)).resolves.toMatchObject({
        verified: true,
      });
      expect(f.gateway.addFields).not.toHaveBeenCalled();
      expect(f.gateway.createSchema).not.toHaveBeenCalled();
    },
  );

  it.each([false, true])(
    "rejects an identical-field replacement before any write (already converged: %s)",
    async (converged) => {
      const f = fixture(converged);
      const plan = await f.service.plan();
      f.replace();
      await expect(f.service.applyPlan(plan)).rejects.toThrow(
        "schema ID drifted after PLAN",
      );
      expect(f.gateway.addFields).not.toHaveBeenCalled();
      expect(f.gateway.createSchema).not.toHaveBeenCalled();
    },
  );

  it.each([false, true])(
    "rejects replacement after mutation and does not retry the writer (lost response: %s)",
    async (lostResponse) => {
      const f = fixture();
      const plan = await f.service.plan();
      f.gateway.addFields.mockImplementation(async () => {
        f.replace();
        if (lostResponse) throw new Error("response_lost");
      });
      await expect(f.service.applyPlan(plan)).rejects.toThrow(
        "schema ID drifted after PLAN",
      );
      await expect(f.service.applyPlan(plan)).rejects.toThrow(
        "schema ID drifted after PLAN",
      );
      expect(f.gateway.addFields).toHaveBeenCalledOnce();
      expect(f.gateway.createSchema).not.toHaveBeenCalled();
    },
  );

  it("retains the reviewed ID and freshly rejects replacement in read-only verification", async () => {
    const f = fixture(true);
    const plan = await f.service.plan();
    if (plan.kind !== "unchanged")
      throw new Error("expected unchanged fixture");
    await expect(f.service.readReviewedSchema(plan)).resolves.toEqual({
      schemaId: "schema-original",
      managedSlice: plan.after,
    });
    f.replace();
    await expect(f.service.readReviewedSchema(plan)).rejects.toThrow(
      "schema ID drifted after PLAN",
    );
    expect(f.gateway.readSchema).toHaveBeenCalledTimes(3);
    expect(f.gateway.addFields).not.toHaveBeenCalled();
    expect(f.gateway.createSchema).not.toHaveBeenCalled();
  });
});
