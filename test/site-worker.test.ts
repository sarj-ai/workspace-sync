import { describe, expect, it, vi } from "vitest";

import worker from "../site/worker.ts";

describe("documentation routing", () => {
  it("retains the query when canonicalizing the project root", async () => {
    const fetch = vi.fn();
    const response = await worker.fetch(
      new Request(
        "https://sarj.ai/engineering/projects/workspace-sync?from=hub",
      ),
      { ASSETS: { fetch } },
    );
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      "https://sarj.ai/engineering/projects/workspace-sync/?from=hub",
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    "/engineering/projects/other/",
    "/.git/config",
    "/engineering/projects/workspace-sync-foreign/",
  ])("refuses unrelated route %s", async (path) => {
    const fetch = vi.fn();
    const response = await worker.fetch(new Request(`https://sarj.ai${path}`), {
      ASSETS: { fetch },
    });
    expect(response.status).toBe(404);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["POST", "PUT", "DELETE", "PATCH"])(
    "refuses %s without contacting assets",
    async (method) => {
      const fetch = vi.fn();
      const response = await worker.fetch(
        new Request("https://sarj.ai/engineering/projects/workspace-sync/", {
          method,
        }),
        { ASSETS: { fetch } },
      );
      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toBe("GET, HEAD");
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["GET", "HEAD"])(
    "uses native static-asset handling for %s",
    async (method) => {
      const response = new Response("documentation");
      const fetch = vi.fn().mockResolvedValue(response);
      const request = new Request(
        "https://sarj.ai/engineering/projects/workspace-sync/api/",
        { method },
      );
      await expect(worker.fetch(request, { ASSETS: { fetch } })).resolves.toBe(
        response,
      );
      expect(fetch).toHaveBeenCalledExactlyOnceWith(request);
    },
  );
});

it.each(["", "/", "/api/?keep=one&keep=two"])(
  "redirects legacy engineering%s directly to the new mount",
  async (path) => {
    const fetch = vi.fn();
    const response = await worker.fetch(
      new Request(`https://engineering.sarj.ai/projects/workspace-sync${path}`),
      { ASSETS: { fetch } },
    );
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(
      `https://sarj.ai/engineering/projects/workspace-sync${path === "" ? "/" : path}`,
    );
    expect(fetch).not.toHaveBeenCalled();
  },
);
