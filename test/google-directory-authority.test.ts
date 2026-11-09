import { describe, expect, it } from "vitest";

import {
  googleAuthorityFingerprintRecord,
  mergeGoogleDirectoryAuthority,
} from "../src/org-sync/google-directory-authority.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";

const ORDINARY: GoogleDirectoryUser = {
  id: "ordinary-google-user",
  primaryEmail: "employee@company.test",
  isAdmin: false,
  isDelegatedAdmin: false,
};

describe("Google privilege evidence fingerprints", () => {
  it.each(["isAdmin", "isDelegatedAdmin"] as const)(
    "distinguishes unknown %s from false",
    (field) => {
      const unknown = { ...ORDINARY, [field]: undefined };
      expect(googleAuthorityFingerprintRecord(unknown)[field]).toBeNull();
      expect(googleAuthorityFingerprintRecord(ORDINARY)[field]).toBe(false);
      expect(() =>
        mergeGoogleDirectoryAuthority([ORDINARY, unknown], []),
      ).toThrow(
        "workspace_directory_google_identity_conflict:ordinary-google-user",
      );
      expect(() =>
        mergeGoogleDirectoryAuthority([unknown, ORDINARY], []),
      ).toThrow(
        "workspace_directory_google_identity_conflict:ordinary-google-user",
      );
    },
  );
});
