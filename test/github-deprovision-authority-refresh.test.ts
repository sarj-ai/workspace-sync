import { describe, expect, it, vi } from "vitest";

import { refreshGitHubDeprovisionAuthoritySnapshot } from "../src/identity-provisioning/refresh-git-hub-deprovision-authority-snapshot.ts";

const CAPTURED_AT = "2026-08-31T20:00:00.000Z";

function github(overrides: Record<string, unknown> = {}) {
  return {
    capturedAt: CAPTURED_AT,
    errors: [],
    invitations: [],
    members: [],
    organization: { id: 100_000_001, login: "example" },
    outsideCollaborators: [],
    repositories: [],
    teams: [],
    ...overrides,
  };
}

describe("GitHub deprovision authority refresh", () => {
  it.each([
    [
      "capability error",
      {
        errors: [
          { capability: "members", code: "http_503", message: "failed" },
        ],
      },
    ],
    ["missing organization", { organization: null }],
  ])("preserves the previous snapshot on %s", async (_name, override) => {
    const write = vi.fn();

    await expect(
      refreshGitHubDeprovisionAuthoritySnapshot({
        captureGitHub: () => Promise.resolve(github(override)),
        captureGoogle: () => Promise.resolve({ deletedUsers: [], users: [] }),
        now: () => new Date(CAPTURED_AT),
        store: { read: vi.fn(), write },
      }),
    ).rejects.toThrow("github_deprovision_authority_capture_incomplete");
    expect(write).not.toHaveBeenCalled();
  });

  it("writes one complete versioned snapshot and returns bounded counts", async () => {
    const write = vi.fn();
    const result = await refreshGitHubDeprovisionAuthoritySnapshot({
      captureGitHub: () => Promise.resolve(github()),
      captureGoogle: () => Promise.resolve({ deletedUsers: [], users: [] }),
      now: () => new Date(CAPTURED_AT),
      store: { read: vi.fn(), write },
    });

    expect(write).toHaveBeenCalledOnce();
    expect(write).toHaveBeenCalledWith(
      expect.objectContaining({
        capturedAt: CAPTURED_AT,
        schemaVersion: "github-deprovision-authority-snapshot/v1",
      }),
    );
    expect(result).toEqual({
      capturedAt: CAPTURED_AT,
      deletedUsers: 0,
      githubMembers: 0,
      githubRepositories: 0,
      users: 0,
    });
  });
});
