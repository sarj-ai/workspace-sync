import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";

import { GoogleDirectoryAuthorityReader } from "../src/identity-lifecycle/google-directory-authority-reader.ts";
import {
  DIRECTORY_READONLY_SCOPE,
  DIRECTORY_SCOPE,
  GoogleDirectoryClient,
  type GoogleDirectoryClientOptions,
} from "../src/org-sync/google-directory-client.ts";
import {
  GoogleGithubIdentitySchema,
  GoogleImmutableUserIdSchema,
  SARJ_IDENTITY_SCHEMA_FIELDS,
  SarjIdentitySchemaService,
} from "../src/org-sync/google-identity-schema.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";
import { isString } from "./support/value-guards.ts";

async function client(
  fetchImpl: typeof fetch,
  scope: GoogleDirectoryClientOptions["scope"] = DIRECTORY_SCOPE,
): Promise<GoogleDirectoryClient> {
  return new GoogleDirectoryClient({
    adminSubject: "admin@company.test",
    fetchImpl,
    privateKey: await rsaPrivateKeyFixture(),
    scope,
    serviceAccountEmail: "social-bot@example.iam.gserviceaccount.com",
    sleep: () => Promise.resolve(),
    userProject: "workspace-sync-test",
  });
}

function requestUrl(input: RequestInfo | URL): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

function requestJson(init: RequestInit | undefined): unknown {
  if (!isString(init?.body))
    throw new Error("expected a JSON string request body");
  return JSON.parse(init.body) as unknown;
}

describe("Google Directory LinkedIn digest preferences", () => {
  it("parses managed private custom schemas without discarding unknown schemas or fields", async () => {
    const directory = await client(async (input) => {
      if (requestUrl(input).hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      return Response.json({
        users: [
          {
            customSchemas: {
              SarjIdentity: {
                githubLogin: "octocat",
                githubUserId: "583231",
                unrelatedIdentity: "preserved",
              },
              WorkspaceAccount: { isBot: true },
              SocialBot: {
                linkedinDigestOptOut: true,
                unrelatedSetting: "preserved",
              },
              UnrelatedSchema: {
                nested: { enabled: true },
                value: "preserved",
              },
            },
            id: "10001",
            primaryEmail: "person@company.test",
          },
        ],
      });
    });

    const users = await directory.listAllUsers("run-id");

    expect(users[0]?.customSchemas).toEqual({
      SarjIdentity: {
        githubLogin: "octocat",
        githubUserId: "583231",
        unrelatedIdentity: "preserved",
      },
      WorkspaceAccount: { isBot: true },
      SocialBot: { linkedinDigestOptOut: true, unrelatedSetting: "preserved" },
      UnrelatedSchema: { nested: { enabled: true }, value: "preserved" },
    });
  });

  it("patches only the preference field using the immutable user ID and writable scope", async () => {
    let delegatedScope = "";
    let patch: { body: unknown; method: string; url: URL } | undefined;
    const directory = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        const tokenBody =
          init?.body instanceof URLSearchParams
            ? init.body
            : new URLSearchParams();
        const scope = decodeJwt(tokenBody.get("assertion") ?? "").scope;
        delegatedScope = isString(scope) ? scope : "";
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      patch = {
        body: requestJson(init),
        method: init?.method ?? "GET",
        url,
      };
      expect(new Headers(init?.headers).get("content-type")).toBe(
        "application/json",
      );
      expect(new Headers(init?.headers).get("if-match")).toBe('"etag-1"');
      expect(new Headers(init?.headers).get("x-goog-user-project")).toBe(
        "workspace-sync-test",
      );
      return new Response(null, { status: 204 });
    });

    await directory.setLinkedInDigestOptOut(
      " 10001 ",
      true,
      "1724000000.000101",
      ' "etag-1" ',
      "run-id",
    );

    expect(delegatedScope).toBe(
      "https://www.googleapis.com/auth/admin.directory.user",
    );
    expect(patch).toEqual({
      body: {
        customSchemas: {
          SocialBot: {
            linkedinDigestOptOut: true,
            linkedinDigestPreferenceActionTs: "1724000000.000101",
          },
        },
      },
      method: "PATCH",
      url: new URL(
        "https://admin.googleapis.com/admin/directory/v1/users/10001",
      ),
    });
  });

  it("writes false for re-enrollment and surfaces final API failures", async () => {
    let body: unknown;
    const directory = await client(async (input, init) => {
      if (requestUrl(input).hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      body = requestJson(init);
      return new Response(null, { status: 403 });
    });

    await expect(
      directory.setLinkedInDigestOptOut(
        "10001",
        false,
        "1724000000.000102",
        "etag-1",
        "run-id",
      ),
    ).rejects.toThrow("Google Directory users.patch HTTP 403");
    expect(body).toEqual({
      customSchemas: {
        SocialBot: {
          linkedinDigestOptOut: false,
          linkedinDigestPreferenceActionTs: "1724000000.000102",
        },
      },
    });
  });

  it("rejects writes from a read-only client before requesting a token", async () => {
    let requests = 0;
    const directory = await client(async () => {
      requests++;
      return new Response(null, { status: 500 });
    }, DIRECTORY_READONLY_SCOPE);

    await expect(
      directory.setLinkedInDigestOptOut(
        "10001",
        true,
        "1724000000.000101",
        "etag-1",
        "run-id",
      ),
    ).rejects.toThrow("require the writable user scope");
    expect(requests).toBe(0);
  });

  it("rejects an email or blank key instead of accidentally patching by a mutable identifier", async () => {
    let requests = 0;
    const directory = await client(async () => {
      requests++;
      return new Response(null, { status: 500 });
    });

    await expect(
      directory.setLinkedInDigestOptOut(
        "person@company.test",
        true,
        "1724000000.000101",
        "etag-1",
        "run-id",
      ),
    ).rejects.toThrow("numeric immutable Google Directory user ID");
    await expect(
      directory.setLinkedInDigestOptOut(
        " ",
        true,
        "1724000000.000101",
        "etag-1",
        "run-id",
      ),
    ).rejects.toThrow("numeric immutable Google Directory user ID");
    expect(requests).toBe(0);
  });

  it("gets only the fields needed for identity state and optimistic concurrency", async () => {
    let directoryUrl: undefined | URL;
    const directory = await client(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      directoryUrl = url;
      return Response.json({
        aliases: ["private-alias@company.test"],
        customSchemas: {
          SocialBot: {
            linkedinDigestOptOut: true,
            linkedinDigestPreferenceActionTs: "1724000000.000101",
          },
        },
        etag: "etag-1",
        id: "10001",
        primaryEmail: "private@company.test",
      });
    });

    const user = await directory.getUserByEmail(
      " Person@company.test ",
      "run-id",
    );

    expect(directoryUrl?.pathname).toBe(
      "/admin/directory/v1/users/person%40company.test",
    );
    expect(directoryUrl?.searchParams.get("fields")).toBe(
      "id,suspended,archived,deletionTime,etag,customSchemas",
    );
    expect(directoryUrl?.searchParams.get("customFieldMask")).toBe("SocialBot");
    expect(user).toEqual({
      customSchemas: {
        SocialBot: {
          linkedinDigestOptOut: true,
          linkedinDigestPreferenceActionTs: "1724000000.000101",
        },
      },
      etag: "etag-1",
      id: "10001",
    });
    expect(user).not.toHaveProperty("primaryEmail");
    expect(user).not.toHaveProperty("aliases");
  });

  it("verifies preferences and reads roster flags without requiring the optional bot schema", async () => {
    const directoryUrls: URL[] = [];
    const directory = await client(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      directoryUrls.push(url);
      if (url.pathname.endsWith("/schemas/SocialBot")) {
        return Response.json({
          fields: [
            {
              fieldName: "linkedinDigestOptOut",
              fieldType: "BOOL",
              multiValued: false,
              readAccessType: "ADMINS_AND_SELF",
            },
            {
              fieldName: "linkedinDigestPreferenceActionTs",
              fieldType: "STRING",
              multiValued: false,
              readAccessType: "ADMINS_AND_SELF",
            },
          ],
          schemaName: "SocialBot",
        });
      }
      return Response.json({
        users: [
          {
            id: "10001",
            primaryEmail: "person@company.test",
            websites: [
              {
                customType: "LinkedIn",
                type: "custom",
                value: "https://www.linkedin.com/in/person",
              },
            ],
          },
        ],
      });
    });

    await directory.verifyLinkedInDigestSchema("run-id");
    await directory.listLinkedInDigestUsers("run-id");

    const usersUrl = directoryUrls.find((url) =>
      url.pathname.endsWith("/users"),
    );
    expect(usersUrl?.searchParams.get("customFieldMask")).toBeNull();
    expect(usersUrl?.searchParams.get("projection")).toBe("full");
    expect(usersUrl?.searchParams.get("fields")).toBe(
      "nextPageToken,users(id,name,primaryEmail,suspended,archived,deletionTime,websites,customSchemas)",
    );
  });
});

describe("Google Directory GitHub identity updates", () => {
  it("resolves exact deleted authority across pages without changing filtered bulk projections", async () => {
    const deletedUser = {
      deletionTime: "2026-09-08T09:13:00Z",
      id: "999999999999999999999",
      primaryEmail: "shared@company.test",
    };
    const otherDeleted = {
      deletionTime: "2026-09-09T09:13:00Z",
      id: "10002",
      primaryEmail: "former@company.test",
    };
    const replacement = { id: "10003", primaryEmail: deletedUser.primaryEmail };
    const directory = await client(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com")
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      if (url.pathname.endsWith(`/users/${deletedUser.id}`))
        return new Response(null, { status: 404 });
      if (url.searchParams.get("showDeleted") === "true")
        return Response.json(
          url.searchParams.has("pageToken")
            ? { users: [deletedUser] }
            : { nextPageToken: "next", users: [otherDeleted] },
        );
      return Response.json({ users: [replacement] });
    }, DIRECTORY_READONLY_SCOPE);

    await expect(directory.listDeletedUsers("bulk")).resolves.toEqual([
      otherDeleted,
    ]);
    await expect(
      directory.listDeletedIdentityUsers("identity"),
    ).resolves.toEqual([otherDeleted]);
    await expect(directory.listAllUsers("active")).resolves.toEqual([
      replacement,
    ]);
    const reader = new GoogleDirectoryAuthorityReader(directory);
    await expect(
      reader.getUserById(deletedUser.id, "authority"),
    ).resolves.toEqual(deletedUser);
  });

  it("propagates a live authority permission failure without falling back to deleted users", async () => {
    const requests: URL[] = [];
    const directory = await client(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com")
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      requests.push(url);
      return new Response(null, { status: 403 });
    }, DIRECTORY_READONLY_SCOPE);

    await expect(
      new GoogleDirectoryAuthorityReader(directory).getUserById(
        "999999999999999999999",
        "denied",
      ),
    ).rejects.toThrow("Google Directory users.get HTTP 403");
    expect(requests).toHaveLength(1);
    expect(requests[0]?.searchParams.has("showDeleted")).toBe(false);
  });

  it.each([
    {
      description: "duplicate",
      deletionTime: "2026-09-08T09:13:00Z",
      duplicate: true,
    },
    {
      description: "invalid deletion time",
      deletionTime: "invalid",
      duplicate: false,
    },
  ])(
    "rejects $description in complete deleted authority",
    async ({ deletionTime, duplicate }) => {
      const deletedUser = {
        deletionTime,
        id: "999999999999999999999",
        primaryEmail: "shared@company.test",
      };
      const directory = await client(async (input) => {
        const url = requestUrl(input);
        if (url.hostname === "oauth2.googleapis.com")
          return Response.json({ "access_token": "token", "expires_in": 3600 });
        if (url.pathname.endsWith(`/users/${deletedUser.id}`))
          return new Response(null, { status: 404 });
        return Response.json({
          users: duplicate ? [deletedUser, deletedUser] : [deletedUser],
        });
      }, DIRECTORY_READONLY_SCOPE);

      await expect(
        new GoogleDirectoryAuthorityReader(directory).getUserById(
          deletedUser.id,
          "invalid",
        ),
      ).rejects.toThrow(
        duplicate
          ? "google_directory_authority_duplicate_deleted_user"
          : "Invalid ISO datetime",
      );
    },
  );

  it("ignores only the approved deleted identity collision while retaining active and other deleted users", async () => {
    const ignoredId = "999999999999999999999";
    const retainedDeletedId = "10002";
    const directory = await client(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      if (url.searchParams.get("showDeleted") === "true") {
        return Response.json({
          users: [
            {
              deletionTime: "2026-09-08T09:13:00Z",
              id: ignoredId,
              primaryEmail: "former-person@company.test",
            },
            {
              deletionTime: "2026-09-09T09:13:00Z",
              id: retainedDeletedId,
              primaryEmail: "former@company.test",
            },
          ],
        });
      }
      return Response.json({
        users: [
          { id: ignoredId, primaryEmail: "active-replacement@company.test" },
        ],
      });
    }, DIRECTORY_READONLY_SCOPE);

    await expect(
      directory.listDeletedUsers("deleted-run"),
    ).resolves.toMatchObject([{ id: retainedDeletedId }]);
    await expect(
      directory.listDeletedIdentityUsers("identity-run"),
    ).resolves.toMatchObject([{ id: retainedDeletedId }]);
    await expect(directory.listAllUsers("active-run")).resolves.toMatchObject([
      { id: ignoredId },
    ]);
  });

  it("captures live and deleted authority inventories with the minimal SarjIdentity mask", async () => {
    const directoryUrls: URL[] = [];
    const directory = await client(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      directoryUrls.push(url);
      return Response.json({ users: [] });
    }, DIRECTORY_READONLY_SCOPE);

    await directory.listIdentityUsers("live-run");
    await directory.listDeletedIdentityUsers("deleted-run");

    expect(directoryUrls).toHaveLength(2);
    for (const url of directoryUrls) {
      expect(url.searchParams.get("projection")).toBe("custom");
      expect(url.searchParams.get("customFieldMask")).toBe("SarjIdentity");
      expect(url.searchParams.get("fields")).toBe(
        "nextPageToken,users(id,primaryEmail,aliases,nonEditableAliases,isAdmin,isDelegatedAdmin,suspended,archived,deletionTime,etag,customSchemas)",
      );
    }
    expect(
      directoryUrls.map((url) => url.searchParams.get("showDeleted")),
    ).toEqual(["false", "true"]);
  });

  it("uses update semantics, immutable ID, and If-Match while preserving every custom field", async () => {
    let update:
      | { body: unknown; headers: Headers; method: string; url: URL }
      | undefined;
    const directory = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ "access_token": "token", "expires_in": 3600 });
      }
      update = {
        body: requestJson(init),
        headers: new Headers(init?.headers),
        method: init?.method ?? "GET",
        url,
      };
      return Response.json({});
    });

    await directory.updateUser({
      expectedEtag: '"user-etag-1"',
      identity: GoogleGithubIdentitySchema.parse({
        githubLogin: "octocat",
        githubUserId: "583231",
      }),
      preservedCustomSchemas: {
        OtherSchema: { accessTier: "gold" },
        SarjIdentity: { existingField: "preserved", githubLogin: "old-login" },
      },
      userId: GoogleImmutableUserIdSchema.parse("10001"),
    });

    expect(update).toMatchObject({
      method: "PUT",
      url: new URL(
        "https://admin.googleapis.com/admin/directory/v1/users/10001",
      ),
    });
    expect(update?.headers.get("if-match")).toBe('"user-etag-1"');
    expect(update?.body).toEqual({
      customSchemas: {
        OtherSchema: { accessTier: "gold" },
        SarjIdentity: {
          existingField: "preserved",
          githubLogin: "octocat",
          githubUserId: "583231",
        },
      },
    });
  });
});

describe("Google Directory SarjIdentity schema gateway", () => {
  it("keeps an unchanged APPLY on the read-only schema scope", async () => {
    const delegatedScopes: string[] = [];
    const methods: string[] = [];
    const directory = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        const tokenBody =
          init?.body instanceof URLSearchParams
            ? init.body
            : new URLSearchParams();
        const scope = decodeJwt(tokenBody.get("assertion") ?? "").scope;
        delegatedScopes.push(isString(scope) ? scope : "");
        return Response.json({
          "access_token": "readonly-token",
          "expires_in": 3600,
        });
      }
      methods.push(init?.method ?? "GET");
      return Response.json({
        displayName: "SarjIdentity",
        etag: '"schema-etag-1"',
        fields: SARJ_IDENTITY_SCHEMA_FIELDS,
        schemaId: "schema-1",
        schemaName: "SarjIdentity",
      });
    });

    await expect(
      new SarjIdentitySchemaService(directory).reconcile("apply"),
    ).resolves.toMatchObject({ plan: { kind: "unchanged" }, verified: true });

    expect(delegatedScopes).toEqual([
      "https://www.googleapis.com/auth/admin.directory.userschema.readonly",
    ]);
    expect(methods).toEqual(["GET", "GET"]);
  });

  it("reads with the read-only schema scope and creates with the write scope", async () => {
    const delegatedScopes: string[] = [];
    let createdBody: unknown;
    const directory = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        const tokenBody =
          init?.body instanceof URLSearchParams
            ? init.body
            : new URLSearchParams();
        const scope = decodeJwt(tokenBody.get("assertion") ?? "").scope;
        delegatedScopes.push(isString(scope) ? scope : "");
        return Response.json({
          "access_token": `token-${String(delegatedScopes.length)}`,
          "expires_in": 3600,
        });
      }
      if (init?.method === "POST") {
        createdBody = requestJson(init);
        return Response.json({});
      }
      return new Response(null, { status: 404 });
    });

    await expect(directory.readSchema("SarjIdentity")).resolves.toBeNull();
    await directory.createSchema({
      displayName: "SarjIdentity",
      fields: SARJ_IDENTITY_SCHEMA_FIELDS,
      schemaName: "SarjIdentity",
    });

    expect(delegatedScopes).toEqual([
      "https://www.googleapis.com/auth/admin.directory.userschema.readonly",
      "https://www.googleapis.com/auth/admin.directory.userschema",
    ]);
    expect(createdBody).toEqual({
      displayName: "SarjIdentity",
      fields: SARJ_IDENTITY_SCHEMA_FIELDS,
      schemaName: "SarjIdentity",
    });
  });

  it("adds fields with an etag fence while preserving unrelated fields", async () => {
    let delegatedScope = "";
    let update:
      | { body: unknown; headers: Headers; method: string; url: URL }
      | undefined;
    const directory = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") {
        const tokenBody =
          init?.body instanceof URLSearchParams
            ? init.body
            : new URLSearchParams();
        const scope = decodeJwt(tokenBody.get("assertion") ?? "").scope;
        delegatedScope = isString(scope) ? scope : "";
        return Response.json({
          "access_token": "write-token",
          "expires_in": 3600,
        });
      }
      update = {
        body: requestJson(init),
        headers: new Headers(init?.headers),
        method: init?.method ?? "GET",
        url,
      };
      return Response.json({});
    });
    const unrelated = {
      fieldId: "unmanaged-id",
      fieldName: "costCenter",
      fieldType: "STRING" as const,
      indexed: false,
      multiValued: false,
      readAccessType: "ADMINS_AND_SELF",
    };

    await directory.addFields(
      {
        displayName: "SarjIdentity",
        etag: '"schema-etag-1"',
        fields: [SARJ_IDENTITY_SCHEMA_FIELDS[0], unrelated],
        schemaId: "schema/id",
        schemaName: "SarjIdentity",
      },
      [SARJ_IDENTITY_SCHEMA_FIELDS[1]],
    );

    expect(update).toMatchObject({
      method: "PUT",
      url: new URL(
        "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/schemas/schema%2Fid",
      ),
    });
    expect(update?.headers.get("if-match")).toBe('"schema-etag-1"');
    expect(delegatedScope).toBe(
      "https://www.googleapis.com/auth/admin.directory.userschema",
    );
    expect(update?.body).toMatchObject({
      fields: [
        SARJ_IDENTITY_SCHEMA_FIELDS[0],
        unrelated,
        SARJ_IDENTITY_SCHEMA_FIELDS[1],
      ],
      schemaId: "schema/id",
      schemaName: "SarjIdentity",
    });
  });
});
