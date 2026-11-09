import { describe, expect, it, vi } from "vitest";

import type { GitHubDeprovisionAuthority } from "../src/github-access-audit/github-deprovision-authority-contract.ts";
import {
  GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
  GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS,
  type GitHubDeprovisionAuthoritySnapshotInput,
  type GitHubDeprovisionAuthoritySnapshotKvPort,
  type GitHubDeprovisionAuthoritySnapshotStoreError,
  KvGitHubDeprovisionAuthoritySnapshotStore,
} from "../src/identity-provisioning/github-deprovision-authority-snapshot-store.ts";

const NOW = "2026-08-31T12:00:00.000Z";
const GOOGLE_USER_ID = "999999999999999999901";

function githubSnapshot(): GitHubDeprovisionAuthority {
  return {
    capturedAt: NOW,
    errors: [],
    invitations: [],
    members: [{ id: 583_231, login: "octocat", role: "member", type: "User" }],
    organization: { id: 100_000_001, login: "example" },
    outsideCollaborators: [],
    repositories: [],
    teams: [],
  };
}

function snapshot(
  overrides: Partial<GitHubDeprovisionAuthoritySnapshotInput> = {},
): GitHubDeprovisionAuthoritySnapshotInput {
  return {
    capturedAt: NOW,
    github: githubSnapshot(),
    google: {
      complete: true,
      deletedUsers: [
        {
          deletionTime: "2026-08-30T12:00:00.000Z",
          id: "100000000000000000030",
          primaryEmail: "departed@company.test",
        },
      ],
      users: [
        {
          customSchemas: {
            SarjIdentity: { githubLogin: "octocat", githubUserId: "583231" },
          },
          etag: "etag-1",
          id: GOOGLE_USER_ID,
          primaryEmail: "octocat@company.test",
          suspended: true,
        },
      ],
    },
    schemaVersion: GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    ...overrides,
  };
}

function memoryKv(initial: null | string = null) {
  let value = initial;
  const get = vi.fn(async () => value);
  const put = vi.fn(async (_key: string, next: string) => {
    value = next;
  });
  const kv: GitHubDeprovisionAuthoritySnapshotKvPort = { get, put };
  return { get, kv, put };
}

function expectStoreError(
  code: GitHubDeprovisionAuthoritySnapshotStoreError["code"],
) {
  const matcher: unknown = expect.objectContaining({
    code,
    name: "GitHubDeprovisionAuthoritySnapshotStoreError",
  });
  return matcher;
}

describe("KV GitHub deprovision authority snapshot store", () => {
  it("writes and reads one schema-validated versioned snapshot at the stable key", async () => {
    const fixture = memoryKv();
    const store = new KvGitHubDeprovisionAuthoritySnapshotStore(fixture.kv, {
      now: () => Date.parse(NOW),
    });

    await store.write(snapshot());
    const read = await store.read();

    expect(fixture.put).toHaveBeenCalledWith(
      GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      expect.any(String),
      { expirationTtl: GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_TTL_SECONDS },
    );
    expect(fixture.get).toHaveBeenCalledWith(
      GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_KEY,
      "text",
    );
    expect(read).toMatchObject({
      capturedAt: NOW,
      github: { organization: { id: 100_000_001, login: "example" } },
      google: {
        complete: true,
        deletedUsers: [{ id: "100000000000000000030" }],
        users: [{ id: GOOGLE_USER_ID, suspended: true }],
      },
      schemaVersion: GITHUB_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    });
  });

  it("rejects a missing snapshot", async () => {
    const store = new KvGitHubDeprovisionAuthoritySnapshotStore(memoryKv().kv, {
      now: () => Date.parse(NOW),
    });

    await expect(store.read()).rejects.toEqual(expectStoreError("missing"));
  });

  it.each([
    ["invalid JSON", "{"],
    [
      "unknown schema version",
      JSON.stringify({ ...snapshot(), schemaVersion: "future/v2" }),
    ],
    [
      "incomplete Google capture",
      JSON.stringify({ ...snapshot(), google: { complete: false } }),
    ],
    [
      "partial GitHub capture",
      JSON.stringify({ ...snapshot(), github: { capturedAt: NOW } }),
    ],
  ])("rejects malformed persisted data: %s", async (_label, payload) => {
    const store = new KvGitHubDeprovisionAuthoritySnapshotStore(
      memoryKv(payload).kv,
      {
        now: () => Date.parse(NOW),
      },
    );

    await expect(store.read()).rejects.toEqual(expectStoreError("malformed"));
  });

  it("rejects future and stale snapshots while accepting the exact age boundary", async () => {
    const nowMs = Date.parse(NOW);
    const options = { maxAgeMs: 20 * 60 * 1_000, now: () => nowMs };
    const future = JSON.stringify(
      snapshot({ capturedAt: new Date(nowMs + 1).toISOString() }),
    );
    const stale = JSON.stringify(
      snapshot({
        capturedAt: new Date(nowMs - options.maxAgeMs - 1).toISOString(),
      }),
    );
    const boundary = JSON.stringify(
      snapshot({
        capturedAt: new Date(nowMs - options.maxAgeMs).toISOString(),
      }),
    );

    await expect(
      new KvGitHubDeprovisionAuthoritySnapshotStore(
        memoryKv(future).kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("future"));
    await expect(
      new KvGitHubDeprovisionAuthoritySnapshotStore(
        memoryKv(stale).kv,
        options,
      ).read(),
    ).rejects.toEqual(expectStoreError("stale"));
    await expect(
      new KvGitHubDeprovisionAuthoritySnapshotStore(
        memoryKv(boundary).kv,
        options,
      ).read(),
    ).resolves.toMatchObject({
      capturedAt: new Date(nowMs - options.maxAgeMs).toISOString(),
    });
  });

  it("rejects oversized reads and writes before crossing the hard KV payload guard", async () => {
    const maxPayloadBytes = 1_024;
    const options = { maxPayloadBytes, now: () => Date.parse(NOW) };
    const oversizedRead = new KvGitHubDeprovisionAuthoritySnapshotStore(
      memoryKv("x".repeat(maxPayloadBytes + 1)).kv,
      options,
    );
    await expect(oversizedRead.read()).rejects.toEqual(
      expectStoreError("oversized"),
    );

    const fixture = memoryKv();
    const oversizedWrite = new KvGitHubDeprovisionAuthoritySnapshotStore(
      fixture.kv,
      options,
    );
    await expect(
      oversizedWrite.write(
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
                id: GOOGLE_USER_ID,
                primaryEmail: "octocat@company.test",
              },
            ],
          },
        }),
      ),
    ).rejects.toEqual(expectStoreError("oversized"));
    expect(fixture.put).not.toHaveBeenCalled();
  });

  it("rejects invalid write envelopes before touching KV", async () => {
    const fixture = memoryKv();
    const store = new KvGitHubDeprovisionAuthoritySnapshotStore(fixture.kv);

    await expect(
      store.write({
        ...snapshot(),
        schemaVersion: "github-deprovision-authority-snapshot/v2",
      } as never),
    ).rejects.toEqual(expectStoreError("malformed"));
    expect(fixture.put).not.toHaveBeenCalled();
  });

  it("rejects generic audit-only GitHub surfaces instead of persisting them", async () => {
    const fixture = memoryKv();
    const store = new KvGitHubDeprovisionAuthoritySnapshotStore(fixture.kv);

    await expect(
      store.write(
        snapshot({
          github: {
            ...githubSnapshot(),
            samlExternalIdentities: [],
            teams: [],
          } as never,
        }),
      ),
    ).rejects.toEqual(expectStoreError("malformed"));
    expect(fixture.put).not.toHaveBeenCalled();
  });
});
