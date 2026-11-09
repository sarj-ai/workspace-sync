import { beforeAll, describe, expect, it, vi } from "vitest";

import { GoogleAdminDirectoryWatchGateway } from "../src/identity-lifecycle/google-admin-directory-watch-gateway.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

const CHANNEL_ID = "directory-update-channel-0000000000000001";
const RESOURCE_ID = "opaque-google-directory-resource";
const RESOURCE_URI =
  "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&event=update";

let privateKey = "";

beforeAll(async () => {
  privateKey = await rsaPrivateKeyFixture();
});

function requestUrl(input: RequestInfo | URL): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}

function gateway(fetchImpl: typeof fetch) {
  return new GoogleAdminDirectoryWatchGateway({
    adminSubject: "admin@company.test",
    fetchImpl,
    privateKey,
    random: () => 0,
    serviceAccountEmail: "worker@example.iam.gserviceaccount.com",
    sleep: () => Promise.resolve(),
    userProject: "workspace-sync-test",
  });
}

function createInput(channelId = CHANNEL_ID) {
  return {
    address:
      "https://internal-automations.company.test/google-directory/events",
    channelId,
    event: "update" as const,
    token: "a-secure-channel-token-with-32-bytes",
    ttlSeconds: 86_400,
  };
}

function oauthResponse(): Response {
  return Response.json({
    "access_token": "delegated-token",
    "expires_in": 3_600,
  });
}

describe("Google Directory watch gateway", () => {
  it("uses the documented stop endpoint", async () => {
    const requests: URL[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = requestUrl(input);
      requests.push(url);
      return url.hostname === "oauth2.googleapis.com"
        ? oauthResponse()
        : new Response(null, { status: 204 });
    });

    await gateway(fetchImpl).stop({
      channelId: CHANNEL_ID,
      resourceId: RESOURCE_ID,
    });

    expect(requests.at(-1)?.href).toBe(
      "https://www.googleapis.com/admin/directory/v1/channels/stop",
    );
  });

  it("creates a watch with one side-effecting request", async () => {
    let watchRequests = 0;
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") return oauthResponse();
      watchRequests += 1;
      return Response.json({
        expiration: "1788832800000",
        id: CHANNEL_ID,
        resourceId: RESOURCE_ID,
        resourceUri: RESOURCE_URI,
      });
    });

    await expect(gateway(fetchImpl).create(createInput())).resolves.toEqual({
      channelId: CHANNEL_ID,
      event: "update",
      expiresAtMs: 1_788_832_800_000,
      resourceId: RESOURCE_ID,
      resourceUri: RESOURCE_URI,
    });
    expect(watchRequests).toBe(1);
  });

  it.each([
    {
      label: "network timeout",
      response: () => Promise.reject(new Error("watch request timed out")),
    },
    {
      label: "provider 503",
      response: () => Promise.resolve(new Response(null, { status: 503 })),
    },
  ])("does not retry an ambiguous users.watch $label", async ({ response }) => {
    let watchRequests = 0;
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = requestUrl(input);
      if (url.hostname === "oauth2.googleapis.com") return oauthResponse();
      watchRequests += 1;
      return response();
    });

    await expect(gateway(fetchImpl).create(createInput())).rejects.toThrow();
    expect(watchRequests).toBe(1);
  });

  it("rejects a channel ID above the provider limit before authentication or I/O", async () => {
    const fetchImpl = vi.fn<typeof fetch>();

    await expect(
      gateway(fetchImpl).create(createInput("c".repeat(65))),
    ).rejects.toThrow();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
