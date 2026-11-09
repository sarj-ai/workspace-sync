import { describe, expect, it } from "vitest";

import { normalizeIdentityEmail } from "../src/identity-sync/normalize-identity-email.ts";

describe("normalizeIdentityEmail", () => {
  it("produces the same stable join key for whitespace and casing variants", () => {
    expect(normalizeIdentityEmail("  Person.Name@Example.COM  ")).toBe(
      "person.name@example.com",
    );
  });
});
