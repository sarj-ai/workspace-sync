import { z } from "zod";

import { GoogleGroupMemberSchema } from "./channel-model.ts";

const MAX_MEMBER_PAGES = 20;
export const GoogleGroupMembersPageSchema = z.object({
  members: z.array(GoogleGroupMemberSchema).default([]),
  nextPageToken: z.string().optional(),
});

/* A complete direct-membership read is required for exact rename and deletion. */
export async function readExactGroupMembers(
  groupId: string,
  label: string,
  request: (url: string) => Promise<Response>,
): Promise<z.output<typeof GoogleGroupMemberSchema>[]> {
  const members: z.output<typeof GoogleGroupMemberSchema>[] = [];
  const seen = new Set<string>();
  let pageToken = "";
  for (let page = 0; page < MAX_MEMBER_PAGES; page++) {
    if (pageToken && seen.has(pageToken))
      throw new Error(
        "Google group member listing returned a repeated page token",
      );
    if (pageToken) seen.add(pageToken);
    const query = new URLSearchParams({ maxResults: "200" });
    if (pageToken) query.set("pageToken", pageToken);
    // eslint-disable-next-line no-await-in-loop -- The next page depends on this response token.
    const response = await request(
      `https://admin.googleapis.com/admin/directory/v1/groups/${encodeURIComponent(groupId)}/members?${query.toString()}`,
    );
    if (!response.ok) {
      void response.body?.cancel().catch(() => undefined);
      throw new Error(`${label} HTTP ${String(response.status)}`);
    }
    // eslint-disable-next-line no-await-in-loop -- Decode this page before resolving its successor.
    const body: unknown = await response.json();
    const parsed = GoogleGroupMembersPageSchema.parse(body);
    members.push(...parsed.members);
    pageToken = parsed.nextPageToken ?? "";
    if (!pageToken) return members;
  }
  throw new Error("Google group member listing exceeded page limit");
}
