import { describe, expect, it, vi } from "vitest";

import { AttioDeprovisionAuthoritySchema } from "../src/identity-provisioning/attio-deprovision-authority-capture.ts";
import {
  ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
  ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS,
  type AttioDeprovisionAuthoritySnapshotInput,
  type AttioDeprovisionAuthoritySnapshotKvPort,
  type AttioDeprovisionAuthoritySnapshotStoreError,
  KvAttioDeprovisionAuthoritySnapshotStore,
} from "../src/identity-provisioning/attio-deprovision-authority-snapshot-store.ts";

const NOW = "2026-09-01T12:00:00.000Z";
const WORKSPACE_ID = "e41575c4-362a-4be5-9bed-f3faaade5597";

function attioAuthority() {
  return AttioDeprovisionAuthoritySchema.parse({
    capturedAt: NOW,
    complete: true as const,
    scimStatus: "available",
    scimUsers: [
      {
        active: true,
        appRole: "member" as const,
        emails: [{ primary: true, value: "person@company.test" }],
        id: "b86a16a2-8c76-4439-bafb-610fc3bfdbd2",
        lastModified: "2026-08-01T00:00:00.000Z",
        userName: "person@company.test",
      },
    ],
    token: { scopes: ["user_management:read"], workspaceId: WORKSPACE_ID },
    workspaceMembers: [
      {
        accessLevel: "member",
        emailAddress: "person@company.test",
        id: {
          workspaceId: WORKSPACE_ID,
          workspaceMemberId: "b86a16a2-8c76-4439-bafb-610fc3bfdbd2",
        },
      },
    ],
  });
}

function snapshot(
  overrides: Partial<AttioDeprovisionAuthoritySnapshotInput> = {},
): AttioDeprovisionAuthoritySnapshotInput {
  return {
    attio: attioAuthority(),
    capturedAt: NOW,
    google: {
      complete: true,
      deletedUsers: [
        {
          deletionTime: "2026-08-31T12:00:00.000Z",
          id: "100000000000000000030",
          primaryEmail: "departed@company.test",
        },
      ],
      users: [
        {
          aliases: ["alias@company.test"],
          id: "999999999999999999901",
          primaryEmail: "person@company.test",
          suspended: true,
        },
      ],
    },
    schemaVersion: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    ...overrides,
  };
}

function storedSnapshot(
  overrides: Partial<AttioDeprovisionAuthoritySnapshotInput> = {},
) {
  const value = snapshot(overrides);
  return {
    ...value,
    attio:
      overrides.capturedAt === undefined || overrides.attio !== undefined
        ? value.attio
        : AttioDeprovisionAuthoritySchema.parse({
            ...value.attio,
            capturedAt: overrides.capturedAt,
          }),
    digests: { attio: "a".repeat(64), google: "b".repeat(64) },
  };
}

function memoryKv(initial: null | string = null) {
  let value = initial;
  const get = vi.fn(async () => value);
  const put = vi.fn(async (_key: string, next: string) => {
    value = next;
  });
  const kv: AttioDeprovisionAuthoritySnapshotKvPort = { get, put };
  return { get, kv, put };
}

function expectStoreError(
  code: AttioDeprovisionAuthoritySnapshotStoreError["code"],
) {
  const matcher: unknown = expect.objectContaining({
    code,
    name: "AttioDeprovisionAuthoritySnapshotStoreError",
  });
  return matcher;
}

describe("KV Attio deprovision authority snapshot store", () => {
  it("writes and reads one strict, complete, versioned authority value", async () => {
    const fixture = memoryKv();
    const store = new KvAttioDeprovisionAuthoritySnapshotStore(fixture.kv, {
      now: () => Date.parse(NOW),
    });

    await store.write(snapshot());
    await expect(store.read()).resolves.toMatchObject({
      attio: {
        complete: true,
        scimUsers: [{ userName: "person@company.test" }],
        token: { workspaceId: WORKSPACE_ID },
        workspaceMembers: [
          expect.objectContaining({
            accessLevel: "member",
            emailAddress: "person@company.test",
          }),
        ],
      },
      capturedAt: NOW,
      digests: {
        attio: expect.stringMatching(/^[a-f0-9]{64}$/u),
        google: expect.stringMatching(/^[a-f0-9]{64}$/u),
      },
      google: { complete: true },
      schemaVersion: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    });
    expect(fixture.put).toHaveBeenCalledWith(
      ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      expect.any(String),
      { expirationTtl: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS },
    );
    expect(fixture.get).toHaveBeenCalledWith(
      ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      "text",
    );
  });

  it("dual-reads a fresh v2 snapshot and truthfully adapts its successful SCIM authority", async () => {
    const current = storedSnapshot();
    const { scimStatus: _scimStatus, ...legacyAttio } = current.attio;
    const legacyPayload = JSON.stringify({
      ...current,
      attio: legacyAttio,
      digests: { attio: "a".repeat(64), google: current.digests.google },
      schemaVersion: "attio-deprovision-authority-snapshot/v2",
    });
    const get = vi.fn(async (key: string) =>
      key === ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY ? null : legacyPayload,
    );
    const store = new KvAttioDeprovisionAuthoritySnapshotStore(
      { get, put: vi.fn() },
      { now: () => Date.parse(NOW) },
    );

    const adapted = await store.read();

    expect(adapted).toMatchObject({
      attio: { scimStatus: "available" },
      schemaVersion: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    });
    expect(adapted.digests.attio).not.toBe("a".repeat(64));
    expect(get).toHaveBeenNthCalledWith(
      1,
      ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      "text",
    );
    expect(get).toHaveBeenNthCalledWith(
      2,
      "identity-provisioning:attio-deprovision-authority-snapshot:v2",
      "text",
    );
  });

  it("canonicalizes unordered authority arrays before persistence", async () => {
    const first = snapshot({
      attio: AttioDeprovisionAuthoritySchema.parse({
        ...attioAuthority(),
        scimUsers: [
          ...attioAuthority().scimUsers,
          {
            active: false,
            emails: [
              { primary: false, value: "z-alias@company.test" },
              { primary: true, value: "departed@company.test" },
            ],
            id: "ec589ce9-ff46-411a-9704-19408c2b66f3",
            lastModified: "2026-08-30T00:00:00.000Z",
            userName: "departed@company.test",
          },
        ],
        workspaceMembers: [
          {
            accessLevel: "member",
            emailAddress: "departed@company.test",
            id: {
              workspaceId: WORKSPACE_ID,
              workspaceMemberId: "ec589ce9-ff46-411a-9704-19408c2b66f3",
            },
          },
          ...attioAuthority().workspaceMembers,
        ],
      }),
      google: {
        complete: true,
        deletedUsers: [
          ...snapshot().google.deletedUsers,
          {
            deletionTime: "2026-08-30T12:00:00.000Z",
            id: "100000000000000000032",
            primaryEmail: "another-departed@company.test",
          },
        ],
        users: [
          ...snapshot().google.users,
          {
            aliases: ["z@company.test", "a@company.test"],
            id: "100000000000000000031",
            primaryEmail: "another@company.test",
          },
        ],
      },
    });
    const second = snapshot({
      attio: AttioDeprovisionAuthoritySchema.parse({
        ...first.attio,
        scimUsers: first.attio.scimUsers
          .map((user) => ({ ...user, emails: [...user.emails].toReversed() }))
          .toReversed(),
        workspaceMembers: [...first.attio.workspaceMembers].toReversed(),
      }),
      google: {
        complete: true,
        deletedUsers: [...first.google.deletedUsers].toReversed(),
        users: first.google.users
          .map((user) => ({
            ...user,
            ...(!(user.aliases === undefined) && {
              aliases: [...user.aliases].toReversed(),
            }),
          }))
          .toReversed(),
      },
    });
    const left = memoryKv();
    const right = memoryKv();

    await new KvAttioDeprovisionAuthoritySnapshotStore(left.kv).write(first);
    await new KvAttioDeprovisionAuthoritySnapshotStore(right.kv).write(second);

    expect(left.put.mock.calls[0]?.[1]).toBe(right.put.mock.calls[0]?.[1]);
  });

  it("changes only the source digest whose canonical authority changes", async () => {
    const baselineKv = memoryKv();
    const attioChangedKv = memoryKv();
    const googleChangedKv = memoryKv();
    const googleUser = snapshot().google.users[0];
    if (googleUser === undefined)
      throw new Error("google_user_fixture_missing");
    const store = (fixture: ReturnType<typeof memoryKv>) =>
      new KvAttioDeprovisionAuthoritySnapshotStore(fixture.kv);

    await store(baselineKv).write(snapshot());
    await store(attioChangedKv).write(
      snapshot({
        attio: AttioDeprovisionAuthoritySchema.parse({
          ...attioAuthority(),
          scimUsers: [{ ...attioAuthority().scimUsers[0], active: false }],
        }),
      }),
    );
    await store(googleChangedKv).write(
      snapshot({
        google: {
          ...snapshot().google,
          users: [{ ...googleUser, suspended: false }],
        },
      }),
    );

    const written = (fixture: ReturnType<typeof memoryKv>) =>
      JSON.parse(fixture.put.mock.calls[0]?.[1] ?? "{}") as {
        digests: { attio: string; google: string };
      };
    const baseline = written(baselineKv).digests;
    const attioChanged = written(attioChangedKv).digests;
    const googleChanged = written(googleChangedKv).digests;
    expect(attioChanged.attio).not.toBe(baseline.attio);
    expect(attioChanged.google).toBe(baseline.google);
    expect(googleChanged.attio).toBe(baseline.attio);
    expect(googleChanged.google).not.toBe(baseline.google);
  });

  it("rejects absent, malformed, future, and stale values", async () => {
    const nowMs = Date.parse(NOW);
    const options = { maxAgeMs: 20 * 60 * 1_000, now: () => nowMs };
    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(
        memoryKv().kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("missing"));
    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(
        memoryKv("{").kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("malformed"));
    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(
        memoryKv(
          JSON.stringify(
            storedSnapshot({
              capturedAt: "2026-09-01T11:59:00.000Z",
              attio: attioAuthority(),
            }),
          ),
        ).kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("malformed"));
    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(
        memoryKv(
          JSON.stringify(
            storedSnapshot({ capturedAt: new Date(nowMs + 1).toISOString() }),
          ),
        ).kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("future"));
    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(
        memoryKv(
          JSON.stringify(
            storedSnapshot({
              capturedAt: new Date(nowMs - options.maxAgeMs - 1).toISOString(),
            }),
          ),
        ).kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("stale"));
  });

  it("accepts the exact maximum-age boundary", async () => {
    const nowMs = Date.parse(NOW);
    const maxAgeMs = 20 * 60 * 1_000;
    const capturedAt = new Date(nowMs - maxAgeMs).toISOString();
    const store = new KvAttioDeprovisionAuthoritySnapshotStore(
      memoryKv(JSON.stringify(storedSnapshot({ capturedAt }))).kv,
      { maxAgeMs, now: () => nowMs },
    );

    await expect(store.read()).resolves.toMatchObject({ capturedAt });
  });

  it.each([
    [
      "future schema",
      { schemaVersion: "attio-deprovision-authority-snapshot/v4" },
    ],
    [
      "incomplete Google",
      { google: { complete: false, deletedUsers: [], users: [] } },
    ],
    ["incomplete Attio", { attio: { ...attioAuthority(), complete: false } }],
    [
      "SCIM availability contradiction",
      { attio: { ...attioAuthority(), scimStatus: "payment-required" } },
    ],
    ["unknown field", { extra: true }],
  ])(
    "rejects invalid writes before touching KV: %s",
    async (_label, override) => {
      const fixture = memoryKv();
      const store = new KvAttioDeprovisionAuthoritySnapshotStore(fixture.kv);

      await expect(
        store.write({ ...snapshot(), ...override } as never),
      ).rejects.toEqual(expectStoreError("malformed"));
      expect(fixture.put).not.toHaveBeenCalled();
    },
  );

  it("guards reads and writes below the 4 MiB hard maximum", async () => {
    const maxPayloadBytes = 1_024;
    const options = { maxPayloadBytes, now: () => Date.parse(NOW) };
    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(
        memoryKv("x".repeat(maxPayloadBytes + 1)).kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("oversized"));

    const fixture = memoryKv();
    const store = new KvAttioDeprovisionAuthoritySnapshotStore(
      fixture.kv,
      options,
    );
    await expect(
      store.write(
        snapshot({
          google: {
            complete: true,
            deletedUsers: [],
            users: [
              {
                aliases: Array.from(
                  { length: maxPayloadBytes / 8 },
                  (_, index) => `alias-${String(index)}@company.test`,
                ),
                id: "999999999999999999901",
                primaryEmail: "person@company.test",
              },
            ],
          },
        }),
      ),
    ).rejects.toEqual(expectStoreError("oversized"));
    expect(fixture.put).not.toHaveBeenCalled();
  });

  it("rejects an invalid maximum payload configuration", () => {
    expect(
      () =>
        new KvAttioDeprovisionAuthoritySnapshotStore(memoryKv().kv, {
          maxPayloadBytes: 4 * 1_024 * 1_024 + 1,
        }),
    ).toThrow(/hard Workers KV snapshot limit/u);
  });

  it("classifies KV write failures without leaking provider details", async () => {
    const put = vi
      .fn()
      .mockRejectedValueOnce(new Error("private binding failure"));
    const kv = { ...memoryKv().kv, put };

    await expect(
      new KvAttioDeprovisionAuthoritySnapshotStore(kv).write(snapshot()),
    ).rejects.toEqual(expectStoreError("write-failed"));
  });
});
