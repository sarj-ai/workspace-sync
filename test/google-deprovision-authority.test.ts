import { describe, expect, it } from "vitest";

import {
  GitHubDeprovisionGoogleAuthoritySnapshotSchema,
  GitHubDeprovisionGoogleAuthorityUserSchema,
} from "../src/identity-provisioning/github-deprovision-google-authority-contract.ts";
import {
  fingerprintGoogleDeprovisionAuthority,
  resolveGoogleDeprovisionTarget,
  validateGoogleDeprovisionAuthority,
} from "../src/identity-provisioning/google-deprovision-authority.ts";
import type { OperationDiagnostic } from "../src/operations/schemas.ts";

const CAPTURED_AT = "2026-09-01T12:00:00.000Z";
const GOOGLE_ID = "100000000000000000031";
const OTHER_GOOGLE_ID = "100000000000000000030";

function user(
  overrides: Record<string, unknown> = {},
): ReturnType<typeof GitHubDeprovisionGoogleAuthorityUserSchema.parse> {
  return GitHubDeprovisionGoogleAuthorityUserSchema.parse({
    id: GOOGLE_ID,
    isAdmin: false,
    isDelegatedAdmin: false,
    primaryEmail: "person@company.test",
    suspended: true,
    ...overrides,
  });
}

function snapshot(
  users: readonly ReturnType<typeof user>[] = [user()],
  deletedUsers: readonly ReturnType<typeof user>[] = [],
) {
  return GitHubDeprovisionGoogleAuthoritySnapshotSchema.parse({
    capturedAt: CAPTURED_AT,
    deletedUsers,
    users,
  });
}

describe("Google deprovision authority", () => {
  it.each([
    { primaryEmail: "root-admin@company.test" },
    { aliases: ["ROOT-ADMIN@company.test"] },
    { nonEditableAliases: ["root-admin@company.test"] },
    { id: "999999999999999999901" },
    { id: "999999999999999999902" },
    { isAdmin: true },
    { isDelegatedAdmin: true },
    { isAdmin: undefined },
    { isDelegatedAdmin: undefined },
  ])("blocks protected or privilege-unknown targets: %j", (overrides) => {
    const target = user(overrides);
    const diagnostics: OperationDiagnostic[] = [];
    expect(
      resolveGoogleDeprovisionTarget(
        snapshot([target]),
        target.id,
        diagnostics,
      ),
    ).toBeNull();
    expect(diagnostics).toEqual([
      expect.objectContaining({
        code: "protected_google_identity",
        severity: "blocker",
      }),
    ]);
  });

  it("binds privilege evidence into the authority fingerprint", async () => {
    await expect(
      fingerprintGoogleDeprovisionAuthority(snapshot([user()])),
    ).resolves.not.toBe(
      await fingerprintGoogleDeprovisionAuthority(
        snapshot([user({ isAdmin: true })]),
      ),
    );
  });
  it("validates immutable-ID, email-owner, and deleted-timestamp invariants globally", () => {
    const diagnostics = validateGoogleDeprovisionAuthority(
      snapshot(
        [
          user({ aliases: ["shared@company.test"] }),
          user({ id: OTHER_GOOGLE_ID, primaryEmail: "shared@company.test" }),
        ],
        [user({ primaryEmail: "deleted@company.test" })],
      ),
    );

    expect(diagnostics.map(({ code }) => code)).toEqual([
      "duplicate_google_user_id",
      "duplicate_google_user_email",
      "google_deleted_user_invalid",
    ]);
  });

  it("resolves only one exact immutable ID and reports a missing target", () => {
    const authority = snapshot([user()]);
    const foundDiagnostics: OperationDiagnostic[] = [];
    expect(
      resolveGoogleDeprovisionTarget(authority, GOOGLE_ID, foundDiagnostics),
    ).toMatchObject({
      id: GOOGLE_ID,
    });
    expect(foundDiagnostics).toEqual([]);

    const missingDiagnostics: OperationDiagnostic[] = [];
    expect(
      resolveGoogleDeprovisionTarget(
        authority,
        OTHER_GOOGLE_ID,
        missingDiagnostics,
      ),
    ).toBeNull();
    expect(missingDiagnostics).toEqual([
      expect.objectContaining({
        code: "google_identity_missing",
        severity: "blocker",
      }),
    ]);
  });

  it("produces the same fingerprint for reordered users and aliases", async () => {
    const first = snapshot([
      user({ aliases: ["z@company.test", "a@company.test"] }),
      user({ id: OTHER_GOOGLE_ID, primaryEmail: "other@company.test" }),
    ]);
    const second = snapshot([
      user({ id: OTHER_GOOGLE_ID, primaryEmail: "other@company.test" }),
      user({ aliases: ["a@company.test", "z@company.test"] }),
    ]);

    await expect(fingerprintGoogleDeprovisionAuthority(first)).resolves.toBe(
      await fingerprintGoogleDeprovisionAuthority(second),
    );
  });
});
