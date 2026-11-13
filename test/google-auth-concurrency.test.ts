import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";

import {
  GoogleDelegatedAuth,
  type GoogleDelegatedAuthOptions,
} from "../src/org-sync/google-delegated-auth.ts";
import { GoogleDirectoryClient } from "../src/org-sync/google-directory-client.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

const SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly";
async function authWith(
  fetchImpl: typeof fetch,
  overrides: Partial<GoogleDelegatedAuthOptions> = {},
) {
  return new GoogleDelegatedAuth({
    adminSubject: "admin@company.test",
    serviceAccountEmail: "synthetic@example.iam.gserviceaccount.com",
    privateKey: await rsaPrivateKeyFixture(),
    fetchImpl,
    ...overrides,
  });
}
function token(value = "synthetic-value", expiresIn = 3600) {
  return Response.json({ "access_token": value, "expires_in": expiresIn });
}

describe("in-flight Google token ownership", () => {
  it.each([2, 16])(
    "shares one same-budget exchange for %i callers and retains warm reuse",
    async (count) => {
      const gate = Promise.withResolvers<undefined>();
      const started = Promise.withResolvers<undefined>();
      const fetchImpl = vi.fn<typeof fetch>(async () => {
        started.resolve(undefined);
        await gate.promise;
        return token();
      });
      const auth = await authWith(fetchImpl);
      const deadline = count === 2 ? undefined : Date.now() + 30_000;
      const result = Promise.all(
        Array.from({ length: count }, () =>
          auth.accessToken(SCOPE, "run", deadline),
        ),
      );
      await started.promise;
      gate.resolve(undefined);
      await expect(result).resolves.toEqual(
        Array.from({ length: count }, () => "synthetic-value"),
      );
      await expect(auth.accessToken(SCOPE, "warm", deadline)).resolves.toBe(
        "synthetic-value",
      );
      expect(fetchImpl).toHaveBeenCalledOnce();
    },
  );

  it("uses one token exchange for parallel active and deleted Directory inventories", async () => {
    const active = { id: "10001", primaryEmail: "active@company.test" };
    const deleted = {
      id: "10002",
      primaryEmail: "deleted@company.test",
      deletionTime: "2026-09-01T00:00:00Z",
    };
    let oauthRequests = 0;
    let directoryRequests = 0;
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(
        input instanceof Request ? input.url : input.toString(),
      );
      if (url.hostname === "oauth2.googleapis.com") {
        oauthRequests++;
        return token();
      }
      directoryRequests++;
      return Response.json({
        users: [
          url.searchParams.get("showDeleted") === "true" ? deleted : active,
        ],
      });
    });
    const directory = new GoogleDirectoryClient({
      adminSubject: "admin@company.test",
      serviceAccountEmail: "synthetic@example.iam.gserviceaccount.com",
      privateKey: await rsaPrivateKeyFixture(),
      userProject: "synthetic-project",
      fetchImpl,
    });
    await expect(
      Promise.all([
        directory.listAllUsers("active"),
        directory.listDeletedUsers("deleted"),
      ]),
    ).resolves.toEqual([[active], [deleted]]);
    expect(oauthRequests).toBe(1);
    expect(directoryRequests).toBe(2);
  });

  it("shares one existing transient retry loop", async () => {
    const sleep = vi.fn(async () => undefined);
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockImplementation(async () => token());
    const auth = await authWith(fetchImpl, { sleep, random: () => 0 });
    await expect(
      Promise.all([
        auth.accessToken(SCOPE, "first"),
        auth.accessToken(SCOPE, "second"),
      ]),
    ).resolves.toEqual(["synthetic-value", "synthetic-value"]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledOnce();
  });

  it("isolates concurrent scopes and preserves signed issuer, subject and audience", async () => {
    const claims: ReturnType<typeof decodeJwt>[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      if (!(init?.body instanceof URLSearchParams))
        throw new TypeError("Expected form");
      const assertion = init.body.get("assertion");
      if (assertion === null) throw new TypeError("Missing assertion");
      claims.push(decodeJwt(assertion));
      return token(`synthetic-${String(claims.length)}`);
    });
    const auth = await authWith(fetchImpl);
    const scopes = [
      SCOPE,
      "https://www.googleapis.com/auth/admin.directory.group.readonly",
    ];
    const values = await Promise.all(
      scopes.map((scope) => auth.accessToken(scope, "run")),
    );
    expect(new Set(values).size).toBe(2);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(new Set(claims.map((claim) => claim.scope))).toEqual(
      new Set(scopes),
    );
    for (const claim of claims)
      expect(claim).toMatchObject({
        iss: "synthetic@example.iam.gserviceaccount.com",
        sub: "admin@company.test",
        aud: "https://oauth2.googleapis.com/token",
      });
  });

  it("isolates delegated subjects in separate immutable credential instances", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      if (!(init?.body instanceof URLSearchParams))
        throw new TypeError("Expected form");
      const assertion = init.body.get("assertion");
      if (assertion === null) throw new TypeError("Missing assertion");
      return token(decodeJwt(assertion).sub);
    });
    const first = await authWith(fetchImpl, {
      adminSubject: "first@company.test",
    });
    const second = await authWith(fetchImpl, {
      adminSubject: "second@company.test",
    });
    await expect(
      Promise.all([
        first.accessToken(SCOPE, "first"),
        second.accessToken(SCOPE, "second"),
      ]),
    ).resolves.toEqual(["first@company.test", "second@company.test"]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("retains a newer different-deadline owner when the older exchange finishes", async () => {
    const firstGate = Promise.withResolvers<undefined>();
    const secondGate = Promise.withResolvers<undefined>();
    const firstStarted = Promise.withResolvers<undefined>();
    const secondStarted = Promise.withResolvers<undefined>();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      const index = fetchImpl.mock.calls.length;
      if (index === 1) {
        firstStarted.resolve(undefined);
        await firstGate.promise;
        return token("first", 1);
      }
      secondStarted.resolve(undefined);
      await secondGate.promise;
      return token("second");
    });
    const auth = await authWith(fetchImpl);
    const deadline = Date.now() + 30_000;
    const first = auth.accessToken(SCOPE, "first", deadline);
    await firstStarted.promise;
    const second = auth.accessToken(SCOPE, "second", deadline + 10_000);
    await secondStarted.promise;
    firstGate.resolve(undefined);
    await expect(first).resolves.toBe("first");
    const follower = auth.accessToken(SCOPE, "follower", deadline + 10_000);
    secondGate.resolve(undefined);
    await expect(Promise.all([second, follower])).resolves.toEqual([
      "second",
      "second",
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("does not join an expired deadline while an older request is pending", async () => {
    const gate = Promise.withResolvers<undefined>();
    const started = Promise.withResolvers<undefined>();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      started.resolve(undefined);
      await gate.promise;
      return token();
    });
    const auth = await authWith(fetchImpl);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    const deadline = now + 1000;
    const first = auth.accessToken(SCOPE, "first", deadline);
    try {
      await started.promise;
      clock.mockReturnValue(deadline + 1);
      await expect(
        auth.accessToken(SCOPE, "expired", deadline),
      ).rejects.toThrow("deadline exceeded");
      expect(fetchImpl).toHaveBeenCalledOnce();
    } finally {
      gate.resolve(undefined);
      clock.mockRestore();
    }
    await expect(first).resolves.toBe("synthetic-value");
  });

  it("removes failed shared work so a later exchange can recover", async () => {
    const gate = Promise.withResolvers<undefined>();
    const started = Promise.withResolvers<undefined>();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      started.resolve(undefined);
      await gate.promise;
      return new Response(null, { status: 403 });
    });
    const auth = await authWith(fetchImpl);
    const result = Promise.allSettled([
      auth.accessToken(SCOPE, "first"),
      auth.accessToken(SCOPE, "second"),
    ]);
    await started.promise;
    gate.resolve(undefined);
    const results = await result;
    expect(results.map((item) => item.status)).toEqual([
      "rejected",
      "rejected",
    ]);
    expect(fetchImpl).toHaveBeenCalledOnce();
    fetchImpl.mockResolvedValueOnce(token("recovered"));
    await expect(auth.accessToken(SCOPE, "retry")).resolves.toBe("recovered");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("bounds pending scope residency and preserves cache eviction", async () => {
    const gate = Promise.withResolvers<undefined>();
    const started = Promise.withResolvers<undefined>();
    const extraStarted = Promise.withResolvers<undefined>();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      if (fetchImpl.mock.calls.length === 65) started.resolve(undefined);
      if (fetchImpl.mock.calls.length === 66) extraStarted.resolve(undefined);
      await gate.promise;
      return token();
    });
    const auth = await authWith(fetchImpl);
    const calls = Array.from({ length: 65 }, (_, index) =>
      auth.accessToken(`scope-${String(index)}`, "run"),
    );
    const result = Promise.all(calls);
    await started.promise;
    const extra = auth.accessToken("scope-0", "evicted-pending");
    await extraStarted.promise;
    gate.resolve(undefined);
    await result;
    await expect(extra).resolves.toBe("synthetic-value");
    expect(fetchImpl).toHaveBeenCalledTimes(66);
    await auth.accessToken("scope-0", "warm");
    expect(fetchImpl).toHaveBeenCalledTimes(66);
  });
});
