import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  DIRECTORY_READONLY_SCOPE,
  GoogleDirectoryClient,
} from "../src/org-sync/google-directory-client.ts";
import type { GoogleDirectoryUser } from "../src/org-sync/model.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

type BatchPart = Readonly<{ body?: unknown; id?: number; status: number }>;

async function client(fetchImpl: typeof fetch): Promise<GoogleDirectoryClient> {
  return new GoogleDirectoryClient({
    adminSubject: "root-admin@company.test",
    fetchImpl,
    privateKey: await rsaPrivateKeyFixture(),
    scope: DIRECTORY_READONLY_SCOPE,
    serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
    sleep: () => Promise.resolve(),
    userProject: "workspace-sync-test",
  });
}

function user(id: string): GoogleDirectoryUser {
  return {
    id,
    primaryEmail: `${id}@company.test`,
    thumbnailPhotoUrl: `https://photo.test/${id}`,
  };
}

function requestUrl(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : input.toString();
}

function batchResponse(parts: readonly BatchPart[]): Response {
  const boundary = "batch_response";
  const body = `${parts
    .map((part, index) => {
      const id = part.id ?? index;
      let reason = "Error";
      if (part.status === 200) reason = "OK";
      if (part.status === 404) reason = "Not Found";
      return `--${boundary}\r\nContent-Type: application/http\r\nContent-ID: <response-photo-${String(id)}>\r\n\r\nHTTP/1.1 ${String(part.status)} ${reason}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(part.body ?? {})}\r\n`;
    })
    .join("")}--${boundary}--\r\n`;
  return new Response(body, {
    headers: { "content-type": `multipart/mixed; boundary="${boundary}"` },
  });
}

function oauthResponse(): Response {
  return Response.json({ "access_token": "token", "expires_in": 3600 });
}

describe("Google Directory profile photos", () => {
  it("batches path-only requests and embeds allowlisted photos while treating only 404 as missing", async () => {
    let batchCalls = 0;
    const directory = await client(async (input, init) => {
      const url = requestUrl(input);
      if (url.includes("oauth2.googleapis.com")) return oauthResponse();
      batchCalls++;
      expect(url).toBe("https://admin.googleapis.com/batch");
      expect(init?.method).toBe("POST");
      expect(new Headers(init?.headers).get("authorization")).toBe(
        "Bearer token",
      );
      expect(new Headers(init?.headers).get("x-goog-user-project")).toBe(
        "workspace-sync-test",
      );
      const body = z.string().parse(init?.body);
      expect(body).toContain(
        "GET /admin/directory/v1/users/present/photos/thumbnail HTTP/1.1",
      );
      expect(body).toContain(
        "GET /admin/directory/v1/users/missing/photos/thumbnail HTTP/1.1",
      );
      expect(body).not.toContain(
        "https://admin.googleapis.com/admin/directory",
      );
      expect(body).not.toContain("root-admin@company.test");
      expect(body).not.toContain("Bearer token");
      return batchResponse([
        { body: { mimeType: "image/jpeg", photoData: "_9j-2Q" }, status: 200 },
        { status: 404 },
      ]);
    });

    const photos = await directory.listUserPhotos(
      [user("present"), user("missing")],
      "run",
    );
    expect(batchCalls).toBe(1);
    expect(photos).toEqual(
      new Map([["present", "data:image/jpeg;base64,/9j+2Q=="]]),
    );
  });

  it("correlates deliberately out-of-order response parts by Content-ID", async () => {
    const directory = await client(async (input) => {
      if (requestUrl(input).includes("oauth2.googleapis.com"))
        return oauthResponse();
      return batchResponse([
        {
          body: { mimeType: "image/png", photoData: "Ag" },
          id: 1,
          status: 200,
        },
        {
          body: { mimeType: "image/jpeg", photoData: "AQ" },
          id: 0,
          status: 200,
        },
      ]);
    });

    await expect(
      directory.listUserPhotos([user("first"), user("second")], "run"),
    ).resolves.toEqual(
      new Map([
        ["second", "data:image/png;base64,Ag=="],
        ["first", "data:image/jpeg;base64,AQ=="],
      ]),
    );
  });

  it("uses sequential bounded batches", async () => {
    let active = 0;
    let maxActive = 0;
    let batchCalls = 0;
    const directory = await client(async (input) => {
      if (requestUrl(input).includes("oauth2.googleapis.com"))
        return oauthResponse();
      active++;
      maxActive = Math.max(maxActive, active);
      batchCalls++;
      await Promise.resolve();
      const count = batchCalls < 3 ? 20 : 1;
      const response = batchResponse(
        Array.from(
          { length: count },
          () => ({ status: 404 }) satisfies BatchPart,
        ),
      );
      active--;
      return response;
    });

    await directory.listUserPhotos(
      Array.from({ length: 41 }, (_, index) => user(String(index))),
      "run",
    );
    expect(batchCalls).toBe(3);
    expect(maxActive).toBe(1);
  });

  it("accepts a full batch at the maximum safe decoded photo size", async () => {
    const photoData = "A".repeat(333_332);
    const directory = await client(async (input) => {
      if (requestUrl(input).includes("oauth2.googleapis.com"))
        return oauthResponse();
      return batchResponse(
        Array.from(
          { length: 20 },
          () =>
            ({
              body: { mimeType: "image/jpeg", photoData },
              status: 200,
            }) satisfies BatchPart,
        ),
      );
    });

    const photos = await directory.listUserPhotos(
      Array.from({ length: 20 }, (_, index) => user(String(index))),
      "run",
    );
    expect(photos.size).toBe(20);
  });

  it("retries a transient inner response and returns the converged batch", async () => {
    let calls = 0;
    const directory = await client(async (input) => {
      if (requestUrl(input).includes("oauth2.googleapis.com"))
        return oauthResponse();
      calls++;
      if (calls === 1) return batchResponse([{ status: 429 }]);
      return batchResponse([
        { body: { mimeType: "image/jpeg", photoData: "AQ" }, status: 200 },
      ]);
    });

    await expect(
      directory.listUserPhotos([user("present")], "run"),
    ).resolves.toEqual(new Map([["present", "data:image/jpeg;base64,AQ=="]]));
    expect(calls).toBe(2);
  });

  it("retries a transient response-body stream failure", async () => {
    let calls = 0;
    const directory = await client(async (input) => {
      if (requestUrl(input).includes("oauth2.googleapis.com"))
        return oauthResponse();
      calls++;
      if (calls === 1) {
        const stream = new ReadableStream({
          start(controller) {
            controller.error(new Error("connection reset"));
          },
        });
        return new Response(stream, {
          headers: {
            "content-type": "multipart/mixed; boundary=batch_response",
          },
        });
      }
      return batchResponse([{ status: 404 }]);
    });

    await expect(
      directory.listUserPhotos([user("present")], "run"),
    ).resolves.toEqual(new Map());
    expect(calls).toBe(2);
  });

  it("fails closed on transient photo errors and malformed response correlation", async () => {
    for (const response of [
      batchResponse([{ status: 429 }]),
      batchResponse([{ id: 1, status: 404 }]),
      batchResponse([]),
      new Response("{}", { headers: { "content-type": "application/json" } }),
    ]) {
      const directory = await client(async (input) => {
        if (requestUrl(input).includes("oauth2.googleapis.com"))
          return oauthResponse();
        return response.clone();
      });
      await expect(
        directory.listUserPhotos([user("present")], "run"),
      ).rejects.toThrow();
    }
  });

  it("rejects unsafe MIME types and oversized payloads", async () => {
    for (const payload of [
      { mimeType: "image/svg+xml", photoData: "PHN2Zz4=" },
      { mimeType: "image/jpeg", photoData: "A".repeat(400_001) },
    ]) {
      const directory = await client(async (input) => {
        if (requestUrl(input).includes("oauth2.googleapis.com"))
          return oauthResponse();
        return batchResponse([{ body: payload, status: 200 }]);
      });
      await expect(
        directory.listUserPhotos([user("present")], "run"),
      ).rejects.toThrow();
    }
  });
});
