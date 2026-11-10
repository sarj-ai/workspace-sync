import assert from "node:assert/strict";
import { hash } from "node:crypto";
import { readdir, readFile, rename, rm, writeFile } from "node:fs/promises";

import type { AstroIntegration } from "astro";

const POLICY_PATTERN =
  /<meta http-equiv="content-security-policy" content="([^"]+)">/u;

export default function cloudflareArtifacts(
  assetRoot: URL,
  site: URL,
): AstroIntegration {
  return {
    name: "sarj-cloudflare-static-artifacts",
    hooks: {
      "astro:build:start": () =>
        rm(assetRoot, { recursive: true, force: true }),
      "astro:build:done": async ({ dir }) => {
        const entries = await readdir(dir, { recursive: true });
        const paths = entries
          .filter((path) => path.endsWith(".html"))
          .toSorted();
        const documents = await Promise.all(
          paths.map(async (path) => ({
            path,
            document: await readFile(new URL(path, dir), "utf8"),
          })),
        );
        const policy = POLICY_PATTERN.exec(documents[0]?.document ?? "")?.[1];
        assert.ok(policy, "Astro must emit a Content Security Policy");
        const hashes = new Set<string>();
        for (const { document } of documents) {
          for (const match of document.matchAll(
            /<script([^>]*)>([\s\S]*?)<\/script>/gu,
          )) {
            if (/\bsrc=/u.test(match[1] ?? "")) continue;
            hashes.add(`'sha256-${hash("sha256", match[2] ?? "", "base64")}'`);
          }
        }
        const directive = /(script-src-elem [^;]*)(;)/u;
        const current = directive.exec(policy)?.[1];
        assert.ok(current, "CSP must define script-src-elem");
        const additions = [...hashes]
          .toSorted()
          .filter((value) => !current.includes(value));
        const header = policy.replace(
          directive,
          (_match, prefix: string, suffix: string) =>
            `${prefix} ${additions.join(" ")}${suffix}`,
        );
        assert.ok(
          Buffer.byteLength(header, "utf8") < 1950,
          "CSP exceeds Cloudflare's header limit",
        );
        await Promise.all(
          documents.map(({ path, document }) =>
            writeFile(new URL(path, dir), document.replace(POLICY_PATTERN, "")),
          ),
        );
        const generated = await readdir(new URL("generated/", dir));
        await Promise.all(
          generated.map((path) =>
            rename(new URL(`generated/${path}`, dir), new URL(path, dir)),
          ),
        );
        await rm(new URL("generated/", dir), { recursive: true });
        await writeFile(
          new URL("404.html", assetRoot),
          await readFile(new URL("404.html", dir)),
        );
        await writeFile(
          new URL("_headers", assetRoot),
          `/*\n  Content-Security-Policy: ${header}\n  X-Content-Type-Options: nosniff\n  Cross-Origin-Opener-Policy: same-origin\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n`,
        );
        const urls = paths
          .filter((path) => path.endsWith("index.html"))
          .map((path) => new URL(path.slice(0, -10), site).href);
        await writeFile(
          new URL("sitemap.xml", dir),
          `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map((url) => `<url><loc>${url}</loc></url>`).join("")}</urlset>\n`,
        );
      },
    },
  };
}
