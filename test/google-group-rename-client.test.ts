import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  GoogleGroupRenameClient,
  type GoogleGroupRenameDetails,
  type GoogleGroupRenameInput,
  GoogleGroupRenameSourceError,
} from "../src/org-sync/google-group-rename-client.ts";
import { rsaPrivateKeyFixture } from "./support/rsa-private-key-fixture.ts";

const PLAN_INPUT = {
  newEmail: "team-eng-finance@company.test",
  oldEmail: "team-product-eng@company.test",
} satisfies GoogleGroupRenameInput;
const INPUT = {
  ...PLAN_INPUT,
  googleGroupId: "01exactimmutablegroup",
} satisfies GoogleGroupRenameDetails;

describe("Google group exact rename client", () => {
  it("performs a read-only collision plan and normalizes complete paginated members and settings", async () => {
    const harness = await fixture();
    const snapshot = await harness.client.readSnapshot(PLAN_INPUT, "plan-run");

    expect(snapshot).toMatchObject({
      collision: null,
      group: {
        email: INPUT.oldEmail,
        id: INPUT.googleGroupId,
        metadata: {
          aliases: ["finance-alias@company.test"],
          description: "Banking engineering",
          name: "Finance Engineering",
        },
      },
      settings: {
        allowExternalMembers: "false",
        whoCanJoin: "INVITED_CAN_JOIN",
      },
    });
    expect(snapshot.members.map(({ id, role }) => ({ id, role }))).toEqual([
      { id: "member-id", role: "MEMBER" },
      { id: "owner-id", role: "OWNER" },
    ]);
    expect(harness.requests.every(({ method }) => method === "GET")).toBe(true);
    expect(
      harness.requests.some(({ path }) =>
        decodeURIComponent(path).endsWith(`/${INPUT.oldEmail}`),
      ),
    ).toBe(true);
    expect(
      harness.requests.some(({ path }) =>
        decodeURIComponent(path).endsWith(`/${INPUT.newEmail}`),
      ),
    ).toBe(true);
    expect(settingsPaths(harness.requests)).toEqual([
      `/groups/v1/groups/${INPUT.oldEmail}?alt=json`,
    ]);
    expect(harness.settingsAccepts).toEqual(["application/json"]);
    expect(settingsPaths(harness.requests)).not.toContain(
      `/groups/v1/groups/${INPUT.googleGroupId}`,
    );
    expect(harness.scopes).toEqual(
      expect.arrayContaining([
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/apps.groups.settings",
      ]),
    );
  });

  it("PATCHes only the exact immutable ID and proves same-ID email, members, roles, and settings", async () => {
    const harness = await fixture();
    const before = await harness.client.readSnapshot(INPUT, "plan-run");
    await harness.client.renameExact(INPUT, before, "apply-run");

    const writes = harness.requests.filter(({ method }) => method !== "GET");
    expect(writes).toEqual([
      {
        body: JSON.stringify({ email: INPUT.newEmail }),
        method: "PATCH",
        path: `/admin/directory/v1/groups/${INPUT.googleGroupId}`,
      },
    ]);
    expect(harness.scopes).toContain(
      "https://www.googleapis.com/auth/admin.directory.group",
    );
    expect(
      harness.requests.filter(({ path }) =>
        path.startsWith("/groups/v1/groups/"),
      ),
    ).toSatisfy((requests: typeof harness.requests) =>
      requests.every(({ method }) => method === "GET"),
    );
    expect(settingsPaths(harness.requests)).toContain(
      `/groups/v1/groups/${INPUT.oldEmail}?alt=json`,
    );
    expect(settingsPaths(harness.requests)).toContain(
      `/groups/v1/groups/${INPUT.newEmail}?alt=json`,
    );
    expect(
      harness.settingsAccepts.every((value) => value === "application/json"),
    ).toBe(true);
    expect(settingsPaths(harness.requests)).not.toContain(
      `/groups/v1/groups/${INPUT.googleGroupId}`,
    );
  });

  it("fails closed when Groups Settings returns a different resource email", async () => {
    const harness = await fixture({
      settingsEmail: "different-group@company.test",
    });
    let error: unknown;
    try {
      await harness.client.readSnapshot(INPUT, "plan-run");
    } catch (cause: unknown) {
      error = cause;
    }
    expect(error).toBeInstanceOf(GoogleGroupRenameSourceError);
    expect(error).toMatchObject({
      stage: "group-settings-email-mismatch",
    });
    expect(harness.requests.every(({ method }) => method === "GET")).toBe(true);
  });

  it("classifies a Groups Settings authorization refusal without reading its body", async () => {
    const harness = await fixture({ settingsStatus: 403 });
    let error: unknown;
    try {
      await harness.client.readSnapshot(INPUT, "plan-run");
    } catch (cause: unknown) {
      error = cause;
    }
    expect(error).toMatchObject({ stage: "group-settings-http-403" });
    expect(harness.requests.every(({ method }) => method === "GET")).toBe(true);
  });

  it("fails closed when signed details pin the wrong immutable ID", async () => {
    const harness = await fixture();
    await expect(
      harness.client.readSnapshot(
        { ...INPUT, googleGroupId: "wrong-id" },
        "apply-run",
      ),
    ).rejects.toThrow("immutable ID did not match");
    expect(harness.requests.every(({ method }) => method === "GET")).toBe(true);
  });

  it("supports exact post-rename readback when Google does not retain the old email alias", async () => {
    const harness = await fixture({
      oldEmailMissingAfterRename: true,
      retainOldEmailAlias: false,
    });
    const before = await harness.client.readSnapshot(PLAN_INPUT, "plan-run");
    await harness.client.renameExact(INPUT, before, "apply-run");
    const after = await harness.client.readSnapshot(PLAN_INPUT, "verify-run");
    expect(after.group).toMatchObject({
      email: INPUT.newEmail,
      id: INPUT.googleGroupId,
    });
    expect(after.collision).toEqual({
      email: INPUT.newEmail,
      id: INPUT.googleGroupId,
    });
  });

  it("fails closed when an unrelated alias changes during rename", async () => {
    const harness = await fixture({ unrelatedAliasAfterRename: true });
    const before = await harness.client.readSnapshot(INPUT, "plan-run");
    await expect(
      harness.client.renameExact(INPUT, before, "apply-run"),
    ).rejects.toThrow("did not preserve the reviewed snapshot");
  });
});

async function fixture(
  options: {
    oldEmailMissingAfterRename?: boolean;
    retainOldEmailAlias?: boolean;
    settingsEmail?: string;
    settingsStatus?: number;
    unrelatedAliasAfterRename?: boolean;
  } = {},
) {
  const state: GoogleRenameFetchState = {
    renamed: false,
    oldEmailMissingAfterRename: options.oldEmailMissingAfterRename ?? false,
    retainOldEmailAlias: options.retainOldEmailAlias ?? true,
    requests: [],
    scopes: [],
    settingsAccepts: [],
    settingsEmail: options.settingsEmail,
    settingsStatus: options.settingsStatus,
    unrelatedAliasAfterRename: options.unrelatedAliasAfterRename ?? false,
  };
  const client = new GoogleGroupRenameClient({
    adminSubject: "root-admin@company.test",
    fetchImpl: (input, init) =>
      Promise.resolve(googleRenameFetch(input, init, state)),
    privateKey: await rsaPrivateKeyFixture(),
    serviceAccountEmail: "org-sync@example.iam.gserviceaccount.com",
    sleep: () => Promise.resolve(),
    userProject: "workspace-sync-test",
  });
  return {
    client,
    requests: state.requests,
    scopes: state.scopes,
    settingsAccepts: state.settingsAccepts,
  };
}

interface GoogleRenameFetchState {
  oldEmailMissingAfterRename: boolean;
  renamed: boolean;
  requests: { body: null | string; method: string; path: string }[];
  retainOldEmailAlias: boolean;
  scopes: string[];
  settingsAccepts: string[];
  settingsEmail: string | undefined;
  settingsStatus: number | undefined;
  unrelatedAliasAfterRename: boolean;
}

function googleRenameFetch(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  state: GoogleRenameFetchState,
): Response {
  const url = new URL(input instanceof Request ? input.url : input.toString());
  if (url.hostname === "oauth2.googleapis.com")
    return oauthResponse(init, state);
  const method = init?.method ?? "GET";
  state.requests.push({
    body: z.string().nullable().catch(null).parse(init?.body),
    method,
    path: `${url.pathname}${url.search}`,
  });
  if (method === "PATCH") return patchResponse(state);
  if (url.hostname === "www.googleapis.com") {
    state.settingsAccepts.push(new Headers(init?.headers).get("accept") ?? "");
    return settingsResponse(state);
  }
  if (url.pathname.endsWith("/members")) return membersResponse(url);
  return groupResponse(url, state);
}

function oauthResponse(
  init: RequestInit | undefined,
  state: GoogleRenameFetchState,
): Response {
  const body =
    init?.body instanceof URLSearchParams ? init.body.toString() : "";
  const assertion = new URLSearchParams(body).get("assertion") ?? "";
  const scope = decodeJwt(assertion).scope;
  const parsedScope = z.string().safeParse(scope);
  if (parsedScope.success) state.scopes.push(parsedScope.data);
  return Response.json({
    "access_token": `token-${String(state.scopes.length)}`,
    "expires_in": 3600,
  });
}

function patchResponse(state: GoogleRenameFetchState): Response {
  state.renamed = true;
  return Response.json({ email: INPUT.newEmail, id: INPUT.googleGroupId });
}

function settingsResponse(state: GoogleRenameFetchState): Response {
  if (state.settingsStatus !== undefined) {
    return new Response("provider body must remain unread", {
      status: state.settingsStatus,
    });
  }
  return Response.json({
    allowExternalMembers: "false",
    email:
      state.settingsEmail ?? (state.renamed ? INPUT.newEmail : INPUT.oldEmail),
    etag: state.renamed ? "after-etag" : "before-etag",
    kind: "groupsSettings#groups",
    whoCanJoin: "INVITED_CAN_JOIN",
  });
}

function membersResponse(url: URL): Response {
  return url.searchParams.has("pageToken")
    ? Response.json({
        members: [
          {
            email: "member@company.test",
            id: "member-id",
            role: "MEMBER",
            status: "ACTIVE",
            type: "USER",
          },
        ],
      })
    : Response.json({
        members: [
          {
            email: "owner@company.test",
            id: "owner-id",
            role: "OWNER",
            status: "ACTIVE",
            type: "USER",
          },
        ],
        nextPageToken: "next",
      });
}

function groupResponse(url: URL, state: GoogleRenameFetchState): Response {
  const key = decodeURIComponent(url.pathname.split("/").at(-1) ?? "");
  if (key === INPUT.newEmail && !state.renamed)
    return new Response(null, { status: 404 });
  if (
    key === INPUT.oldEmail &&
    state.renamed &&
    state.oldEmailMissingAfterRename
  ) {
    return new Response(null, { status: 404 });
  }
  const aliases = ["FINANCE-ALIAS@COMPANY.TEST"];
  if (state.renamed && state.retainOldEmailAlias) aliases.push(INPUT.oldEmail);
  if (state.renamed && state.unrelatedAliasAfterRename)
    aliases.push("unreviewed@company.test");
  return Response.json({
    aliases,
    description: "Banking engineering",
    email: state.renamed ? INPUT.newEmail : INPUT.oldEmail,
    id: INPUT.googleGroupId,
    name: "Finance Engineering",
  });
}

function settingsPaths(requests: GoogleRenameFetchState["requests"]): string[] {
  return requests
    .map(({ path }) => decodeURIComponent(path))
    .filter((path) => path.startsWith("/groups/v1/groups/"));
}
