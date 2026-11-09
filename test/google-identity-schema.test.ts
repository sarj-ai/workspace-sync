import { describe, expect, it, vi } from "vitest";

import {
  GoogleGithubIdentityService,
  type GoogleWorkspaceIdentitySchemaGateway,
  type GoogleWorkspaceIdentityUserGateway,
  SARJ_IDENTITY_SCHEMA_FIELDS,
  SarjIdentitySchemaCompatibilityError,
  SarjIdentitySchemaService,
} from "../src/org-sync/google-identity-schema.ts";

function schemaSnapshot(
  fields: readonly unknown[] = SARJ_IDENTITY_SCHEMA_FIELDS,
) {
  return {
    displayName: "SarjIdentity",
    etag: '"schema-etag-1"',
    fields,
    schemaId: "schema-1",
    schemaName: "SarjIdentity",
  };
}

describe("Google user identity write budget", () => {
  it("rejects exhausted budget before update and outside ambiguous write recovery", async () => {
    const updateUser = vi.fn();
    const readUserById = vi.fn(async () => activeUser());
    const service = new GoogleGithubIdentityService({
      readUserById,
      updateUser,
    });
    const plan = await service.plan({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      userId: "10001",
    });
    const reserve = vi
      .fn()
      .mockRejectedValue(new Error("identity_budget_exhausted"));
    await expect(
      service.applyPlan(plan, { required: true, reserve }),
    ).rejects.toThrow("identity_budget_exhausted");
    expect(reserve).toHaveBeenCalledExactlyOnceWith("10001");
    expect(updateUser).not.toHaveBeenCalled();
    expect(readUserById).toHaveBeenCalledTimes(2);
  });

  it("does not reserve for drifted or already converged identities", async () => {
    let user = activeUser();
    const updateUser = vi.fn();
    const service = new GoogleGithubIdentityService({
      readUserById: async () => user,
      updateUser,
    });
    const desired = { githubLogin: "octocat", githubUserId: "583231" };
    const plan = await service.plan({ desired, userId: "10001" });
    const reserve = vi.fn();
    user = { ...user, etag: "changed" };
    await expect(
      service.applyPlan(plan, { required: true, reserve }),
    ).rejects.toThrow("drifted after PLAN");
    user = activeUser(desired);
    await expect(
      service.applyPlan(plan, { required: true, reserve }),
    ).resolves.toMatchObject({
      verified: true,
    });
    expect(reserve).not.toHaveBeenCalled();
    expect(updateUser).not.toHaveBeenCalled();
  });
});

describe("SarjIdentity Google Workspace schema", () => {
  it("plans exact indexed single-value private fields without writing in dry-run mode", async () => {
    const calls: string[] = [];
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async () => {
        calls.push("add");
      },
      createSchema: async () => {
        calls.push("create");
      },
      readSchema: async () => null,
    };

    const result = await new SarjIdentitySchemaService(gateway).reconcile(
      "dry-run",
    );

    expect(result).toMatchObject({ mode: "dry-run", plan: { kind: "create" } });
    expect(result.plan).toMatchObject({
      after: {
        fields: SARJ_IDENTITY_SCHEMA_FIELDS,
        schemaName: "SarjIdentity",
      },
      before: { fields: [], schemaName: null },
      fields: SARJ_IDENTITY_SCHEMA_FIELDS,
    });
    expect(calls).toEqual([]);
  });

  it("creates a missing schema and requires an exact read-back before succeeding", async () => {
    let created = false;
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async () => undefined,
      createSchema: async (input) => {
        expect(input).toEqual({
          displayName: "SarjIdentity",
          fields: SARJ_IDENTITY_SCHEMA_FIELDS,
          schemaName: "SarjIdentity",
        });
        created = true;
      },
      readSchema: async () => (created ? schemaSnapshot() : null),
    };

    await expect(
      new SarjIdentitySchemaService(gateway).reconcile("apply"),
    ).resolves.toMatchObject({
      mode: "apply",
      plan: { kind: "create" },
      verified: true,
    });
  });

  it("adds only missing managed fields while preserving unrelated schema fields", async () => {
    let added = false;
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async (snapshot, fields) => {
        expect(snapshot.schemaId).toBe("schema-1");
        expect(fields).toEqual([SARJ_IDENTITY_SCHEMA_FIELDS[1]]);
        added = true;
      },
      createSchema: async () => undefined,
      readSchema: async () =>
        schemaSnapshot(
          added
            ? [
                ...SARJ_IDENTITY_SCHEMA_FIELDS,
                {
                  fieldName: "unmanaged",
                  fieldType: "BOOL",
                  readAccessType: "ADMINS_AND_SELF",
                },
              ]
            : [
                SARJ_IDENTITY_SCHEMA_FIELDS[0],
                {
                  fieldName: "unmanaged",
                  fieldType: "BOOL",
                  readAccessType: "ADMINS_AND_SELF",
                },
              ],
        ),
    };

    const result = await new SarjIdentitySchemaService(gateway).reconcile(
      "apply",
    );

    expect(result).toMatchObject({ mode: "apply", verified: true });
  });

  it("blocks incompatible existing fields before any write", async () => {
    let writes = 0;
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async () => {
        writes++;
      },
      createSchema: async () => {
        writes++;
      },
      readSchema: async () =>
        schemaSnapshot([
          { ...SARJ_IDENTITY_SCHEMA_FIELDS[0], indexed: false },
          SARJ_IDENTITY_SCHEMA_FIELDS[1],
        ]),
    };

    await expect(
      new SarjIdentitySchemaService(gateway).reconcile("apply"),
    ).rejects.toBeInstanceOf(SarjIdentitySchemaCompatibilityError);
    expect(writes).toBe(0);
  });

  it("rejects managed drift after PLAN before writing", async () => {
    let current: unknown = schemaSnapshot([SARJ_IDENTITY_SCHEMA_FIELDS[0]]);
    let writes = 0;
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async () => {
        writes++;
      },
      createSchema: async () => {
        writes++;
      },
      readSchema: async () => current,
    };
    const service = new SarjIdentitySchemaService(gateway);
    const reviewed = await service.plan();
    current = schemaSnapshot([
      { ...SARJ_IDENTITY_SCHEMA_FIELDS[0], indexed: false },
    ]);

    await expect(service.applyPlan(reviewed)).rejects.toThrow(
      "drifted after PLAN",
    );
    expect(writes).toBe(0);
  });

  it("treats a concurrently converged create as an idempotent success", async () => {
    let current: unknown = null;
    let writes = 0;
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async () => undefined,
      createSchema: async () => {
        writes++;
      },
      readSchema: async () => current,
    };
    const service = new SarjIdentitySchemaService(gateway);
    const reviewed = await service.plan();
    current = schemaSnapshot();

    await expect(service.applyPlan(reviewed)).resolves.toMatchObject({
      verified: true,
    });
    expect(writes).toBe(0);
  });

  it("accepts a lost mutation response only after exact post-read verification", async () => {
    let current: unknown = null;
    const gateway: GoogleWorkspaceIdentitySchemaGateway = {
      addFields: async () => undefined,
      createSchema: async () => {
        current = schemaSnapshot();
        throw new Error("response_lost_after_commit");
      },
      readSchema: async () => current,
    };
    const service = new SarjIdentitySchemaService(gateway);
    const reviewed = await service.plan();

    await expect(service.applyPlan(reviewed)).resolves.toMatchObject({
      verified: true,
    });
  });
});

function activeUser(identity?: { githubLogin: string; githubUserId: string }) {
  return {
    ...(!(identity === undefined) && {
      customSchemas: { SarjIdentity: identity },
    }),
    etag: "etag-1",
    id: "10001",
    primaryEmail: "person@company.test",
  };
}

describe("Google Workspace GitHub identity mapping", () => {
  it("produces a credential-free dry-run plan without updating the user", async () => {
    let writes = 0;
    const gateway: GoogleWorkspaceIdentityUserGateway = {
      readUserById: async () => activeUser(),
      updateUser: async () => {
        writes++;
      },
    };

    const result = await new GoogleGithubIdentityService(gateway).reconcile({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      mode: "dry-run",
      userId: "10001",
    });

    expect(result.plan.kind).toBe("update");
    expect(writes).toBe(0);
  });

  it("updates by immutable Google ID with etag and verifies the GitHub identity read-back", async () => {
    let identity: { githubLogin: string; githubUserId: string } | undefined;
    const gateway: GoogleWorkspaceIdentityUserGateway = {
      readUserById: async (userId) => {
        expect(userId).toBe("10001");
        return activeUser(identity);
      },
      updateUser: async (input) => {
        expect(input).toEqual({
          expectedEtag: "etag-1",
          identity: { githubLogin: "octocat", githubUserId: "583231" },
          preservedCustomSchemas: {},
          userId: "10001",
        });
        identity = input.identity;
      },
    };

    await expect(
      new GoogleGithubIdentityService(gateway).reconcile({
        desired: { githubLogin: "octocat", githubUserId: "583231" },
        mode: "apply",
        userId: "10001",
      }),
    ).resolves.toMatchObject({ mode: "apply", verified: true });
  });

  it.each([
    { reason: "inactive", state: { suspended: true } },
    { reason: "inactive", state: { archived: true } },
    { reason: "deleted", state: { deletionTime: "2026-08-20T12:00:00.000Z" } },
  ] as const)(
    "blocks inactive and deleted accounts before writing",
    async ({ state, reason }) => {
      let writes = 0;
      const gateway: GoogleWorkspaceIdentityUserGateway = {
        readUserById: async () => ({ ...activeUser(), ...state }),
        updateUser: async () => {
          writes++;
        },
      };

      const result = await new GoogleGithubIdentityService(gateway).reconcile({
        desired: { githubLogin: "octocat", githubUserId: "583231" },
        mode: "dry-run",
        userId: "10001",
      });

      expect(result.plan).toEqual({ kind: "blocked", reason, userId: "10001" });
      expect(writes).toBe(0);
    },
  );

  it("is a verified zero-diff no-op when Google already has the exact identity", async () => {
    let writes = 0;
    const service = new GoogleGithubIdentityService({
      readUserById: async () =>
        activeUser({ githubLogin: "octocat", githubUserId: "583231" }),
      updateUser: async () => {
        writes++;
      },
    });

    await expect(
      service.reconcile({
        desired: { githubLogin: "octocat", githubUserId: "583231" },
        mode: "apply",
        userId: "10001",
      }),
    ).resolves.toMatchObject({ plan: { kind: "unchanged" }, verified: true });
    expect(writes).toBe(0);
  });

  it("rejects ETag drift before writing the reviewed identity", async () => {
    let etag = "etag-1";
    let writes = 0;
    const service = new GoogleGithubIdentityService({
      readUserById: async () => ({ ...activeUser(), etag }),
      updateUser: async () => {
        writes++;
      },
    });
    const plan = await service.plan({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      userId: "10001",
    });
    etag = "etag-2";

    await expect(service.applyPlan(plan)).rejects.toThrow("drifted after PLAN");
    expect(writes).toBe(0);
  });

  it("accepts an ambiguous provider failure only after exact identity readback", async () => {
    let identity: { githubLogin: string; githubUserId: string } | undefined;
    const service = new GoogleGithubIdentityService({
      readUserById: async () => activeUser(identity),
      updateUser: async (input) => {
        identity = input.identity;
        throw new Error("response_lost_after_commit");
      },
    });
    const plan = await service.plan({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      userId: "10001",
    });

    await expect(service.applyPlan(plan)).resolves.toMatchObject({
      verified: true,
    });
  });

  it("retries exact readback while Google propagates a successful identity update", async () => {
    let identity: { githubLogin: string; githubUserId: string } | undefined;
    let postWriteReads = 0;
    const sleeps: number[] = [];
    const service = new GoogleGithubIdentityService(
      {
        readUserById: async () => {
          if (identity === undefined) return activeUser();
          postWriteReads++;
          return postWriteReads < 3 ? activeUser() : activeUser(identity);
        },
        updateUser: async (input) => {
          identity = input.identity;
        },
      },
      {
        readbackDelaysMs: [10, 20, 40],
        sleep: async (delayMs) => {
          sleeps.push(delayMs);
        },
      },
    );
    const plan = await service.plan({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      userId: "10001",
    });

    await expect(service.applyPlan(plan)).resolves.toMatchObject({
      verified: true,
    });
    expect(postWriteReads).toBe(3);
    expect(sleeps).toEqual([10, 20]);
  });

  it("converges when a committed write loses its response and Google readback is initially stale", async () => {
    let identity: { githubLogin: string; githubUserId: string } | undefined;
    let postWriteReads = 0;
    const service = new GoogleGithubIdentityService(
      {
        readUserById: async () => {
          if (identity === undefined) return activeUser();
          postWriteReads++;
          return postWriteReads < 3 ? activeUser() : activeUser(identity);
        },
        updateUser: async (input) => {
          identity = input.identity;
          throw new Error("response_lost_after_commit");
        },
      },
      { readbackDelaysMs: [10, 20], sleep: async () => undefined },
    );
    const plan = await service.plan({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      userId: "10001",
    });

    await expect(service.applyPlan(plan)).resolves.toMatchObject({
      verified: true,
    });
    expect(postWriteReads).toBe(3);
  });

  it("fails closed when an ambiguous mutation cannot be read back", async () => {
    let reads = 0;
    const service = new GoogleGithubIdentityService(
      {
        readUserById: async () => {
          reads++;
          if (reads === 3) throw new Error("readback_unavailable");
          return activeUser();
        },
        updateUser: async () => {
          throw new Error("mutation_response_lost");
        },
      },
      {
        readbackDelaysMs: [10, 20],
        sleep: async () => undefined,
      },
    );
    const plan = await service.plan({
      desired: { githubLogin: "octocat", githubUserId: "583231" },
      userId: "10001",
    });

    await expect(service.applyPlan(plan)).rejects.toThrow(
      "failed exact readback verification",
    );
    expect(reads).toBe(5);
  });
});
