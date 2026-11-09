import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  GoogleGroupDeletionClient,
  type GoogleGroupDeletionDetails,
} from "../src/org-sync/google-group-deletion-client.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

const TARGET = {
  googleGroupEmail: "office-north@company.test",
  googleGroupId: "01retiredgroup",
} satisfies GoogleGroupDeletionDetails;

describe("Google group exact deletion client", () => {
  it("reads by email and immutable ID, then issues one bounded DELETE and verifies both absent", async () => {
    const harness = await fixture();
    const before = await harness.client.readSnapshot(TARGET, "plan-run");
    expect(before).toMatchObject({
      state: "present",
      group: { email: TARGET.googleGroupEmail },
    });
    await harness.client.deleteExact(
      TARGET,
      before as Extract<typeof before, { state: "present" }>,
      "apply-run",
    );
    expect(
      harness.requests.filter(({ method }) => method === "DELETE"),
    ).toEqual([
      {
        method: "DELETE",
        path: `/admin/directory/v1/groups/${TARGET.googleGroupId}`,
      },
    ]);
    await expect(
      harness.client.readSnapshot(TARGET, "verify-run"),
    ).resolves.toEqual({
      state: "absent",
    });
    expect(harness.scopes).toContain(
      "https://www.googleapis.com/auth/admin.directory.group",
    );
  });

  it("treats an ambiguous DELETE failure as success only when both exact lookups prove absence", async () => {
    const harness = await fixture({ deleteResponse: "throw-after-delete" });
    const before = await harness.client.readSnapshot(TARGET, "plan-run");
    await expect(
      harness.client.deleteExact(
        TARGET,
        before as Extract<typeof before, { state: "present" }>,
        "apply-run",
      ),
    ).resolves.toBeUndefined();
    expect(
      harness.requests.filter(({ method }) => method === "DELETE"),
    ).toHaveLength(1);
  });

  it("fails closed without retrying when a failed DELETE leaves either exact lookup present", async () => {
    const harness = await fixture({ deleteResponse: "fail-present" });
    const before = await harness.client.readSnapshot(TARGET, "plan-run");
    await expect(
      harness.client.deleteExact(
        TARGET,
        before as Extract<typeof before, { state: "present" }>,
        "apply-run",
      ),
    ).rejects.toThrow("HTTP 500");
    expect(
      harness.requests.filter(({ method }) => method === "DELETE"),
    ).toHaveLength(1);
  });

  it("ignores Directory metadata churn while retaining the immediate authority reread", async () => {
    const harness = await fixture({ groupMetadataChurn: true });
    const before = await harness.client.readSnapshot(TARGET, "plan-run");
    await expect(
      harness.client.deleteExact(
        TARGET,
        before as Extract<typeof before, { state: "present" }>,
        "apply-run",
      ),
    ).resolves.toBeUndefined();
    expect(
      harness.requests.filter(({ method }) => method === "DELETE"),
    ).toHaveLength(1);
    expect(
      harness.requests.filter(
        ({ method, path }) => method === "GET" && !path.endsWith("/members"),
      ).length,
    ).toBeGreaterThanOrEqual(4);
  });
});

async function fixture(
  options: {
    deleteResponse?: "fail-present" | "throw-after-delete";
    groupMetadataChurn?: boolean;
  } = {},
) {
  const state = {
    deleted: false,
    deleteResponse: options.deleteResponse,
    groupMetadataChurn: options.groupMetadataChurn ?? false,
    groupReadCount: 0,
    requests: [] as { method: string; path: string }[],
    scopes: [] as string[],
  };
  const client = new GoogleGroupDeletionClient({
    adminSubject: "root-admin@company.test",
    fetchImpl: (input, init) => googleDeletionFetch(input, init, state),
    privateKey: await rsaPrivateKeyFixture(),
    serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
    sleep: () => Promise.resolve(),
    userProject: "workspace-sync-test",
  });
  return { client, requests: state.requests, scopes: state.scopes };
}

interface DeletionFetchState {
  deleted: boolean;
  deleteResponse: "fail-present" | "throw-after-delete" | undefined;
  groupMetadataChurn: boolean;
  groupReadCount: number;
  requests: { method: string; path: string }[];
  scopes: string[];
}

function googleDeletionFetch(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  state: DeletionFetchState,
): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  if (url.hostname === "oauth2.googleapis.com")
    return Promise.resolve(oauthResponse(init, state));
  const method = init?.method ?? "GET";
  state.requests.push({ method, path: url.pathname });
  return method === "DELETE"
    ? deleteResponse(state)
    : Promise.resolve(readResponse(url, state));
}

function oauthResponse(
  init: RequestInit | undefined,
  state: DeletionFetchState,
): Response {
  const body =
    init?.body instanceof URLSearchParams ? init.body.toString() : "";
  const scope = decodeJwt(
    new URLSearchParams(body).get("assertion") ?? "",
  ).scope;
  if (z.string().safeParse(scope).success)
    state.scopes.push(z.string().parse(scope));
  return Response.json({ "access_token": "token", "expires_in": 3600 });
}

function deleteResponse(state: DeletionFetchState): Promise<Response> {
  if (state.deleteResponse === "throw-after-delete") {
    state.deleted = true;
    return Promise.reject(new Error("connection reset"));
  }
  if (state.deleteResponse === "fail-present") {
    return Promise.resolve(new Response(null, { status: 500 }));
  }
  state.deleted = true;
  return Promise.resolve(new Response(null, { status: 204 }));
}

function readResponse(url: URL, state: DeletionFetchState): Response {
  if (state.deleted) return new Response(null, { status: 404 });
  if (url.pathname.endsWith("/members")) return Response.json({ members: [] });
  state.groupReadCount += 1;
  return Response.json({
    description: state.groupMetadataChurn
      ? `Retired office group read ${String(state.groupReadCount)}`
      : "Retired office group",
    email: TARGET.googleGroupEmail,
    id: TARGET.googleGroupId,
    name: "Office North",
  });
}
