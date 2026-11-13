import { describe, expect, it } from "vitest";

import { fingerprintGoogleAuthority } from "../src/execution/runtime.ts";
import { fingerprintGoogleDirectoryAuthority } from "../src/org-sync/fingerprint-google-directory-authority.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";

const USERS: [GoogleDirectoryUser, GoogleDirectoryUser] = [
  {
    id: "202",
    primaryEmail: " SECOND@COMPANY.TEST ",
    aliases: ["B@company.test", "a@company.test"],
    isAdmin: false,
    isDelegatedAdmin: false,
    customSchemas: {
      SarjIdentity: { githubLogin: "second", githubUserId: "2" },
    },
  },
  {
    id: "101",
    primaryEmail: "first@company.test",
    deletionTime: "2026-01-01T00:00:00Z",
  },
];
const EXPECTED =
  "87100a232cb9e1b50dc8d89e2f0886fbdc035ebc738518bd89baba1f9d7b6d67";

describe("Google authority fingerprint compatibility", () => {
  it("keeps the existing empty and complete-record hashes", async () => {
    await expect(fingerprintGoogleDirectoryAuthority([])).resolves.toBe(
      "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    );
    await expect(fingerprintGoogleDirectoryAuthority(USERS)).resolves.toBe(
      EXPECTED,
    );
    await expect(fingerprintGoogleAuthority(USERS)).resolves.toBe(EXPECTED);
  });

  it("normalizes emails and alias order, sorts IDs, and preserves inputs", async () => {
    const before = structuredClone(USERS);
    const input = structuredClone(USERS).toReversed();
    for (const user of input) {
      user.primaryEmail = user.primaryEmail.trim().toLowerCase();
      if (user.aliases !== undefined) user.aliases = user.aliases.toReversed();
    }
    const normalizedBefore = structuredClone(input);
    await expect(fingerprintGoogleDirectoryAuthority(input)).resolves.toBe(
      EXPECTED,
    );
    expect(input).toEqual(normalizedBefore);
    expect(USERS).toEqual(before);
  });

  it.each([
    { archived: true },
    { aliases: ["different@company.test"] },
    { deletionTime: "2026-02-01T00:00:00Z" },
    {
      customSchemas: {
        SarjIdentity: { githubLogin: "different", githubUserId: "2" },
      },
    },
    {
      customSchemas: {
        SarjIdentity: { githubLogin: "second", githubUserId: "3" },
      },
    },
    { id: "303" },
    { isAdmin: true },
    { isDelegatedAdmin: true },
    { nonEditableAliases: ["historical@company.test"] },
    { primaryEmail: "different@company.test" },
    { suspended: true },
  ] satisfies Partial<GoogleDirectoryUser>[])(
    "binds every authority field: %j",
    async (change) => {
      const input = structuredClone(USERS);
      Object.assign(input[0], change);
      await expect(
        fingerprintGoogleDirectoryAuthority(input),
      ).resolves.not.toBe(EXPECTED);
    },
  );

  it("distinguishes unknown privilege evidence from false", async () => {
    const input = structuredClone(USERS);
    delete input[0].isAdmin;
    await expect(fingerprintGoogleDirectoryAuthority(input)).resolves.not.toBe(
      EXPECTED,
    );
  });

  it("preserves stable input order for tied IDs", async () => {
    const input = USERS.map((user) => ({ ...user, id: "same" }));
    const reversed = await fingerprintGoogleDirectoryAuthority(
      input.toReversed(),
    );
    await expect(fingerprintGoogleDirectoryAuthority(input)).resolves.not.toBe(
      reversed,
    );
  });

  it.each([
    ["archived", NaN],
    ["suspended", Infinity],
    ["id", undefined],
    ["aliases", [3]],
  ])("rejects malformed projected %s asynchronously", async (field, value) => {
    const input = structuredClone(USERS);
    Reflect.set(input[0], field, value);
    await expect(fingerprintGoogleDirectoryAuthority(input)).rejects.toThrow();
    await expect(fingerprintGoogleAuthority(input)).rejects.toThrow();
  });
});
