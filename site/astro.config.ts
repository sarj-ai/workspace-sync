import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import react from "@astrojs/react";
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

import metadata from "../package.json" with { type: "json" };
import cloudflareArtifacts from "./src/integrations/cloudflare-artifacts.ts";
import { SIDEBAR } from "./src/lib/sidebar.ts";

const SITE = new URL(metadata.homepage);

export default defineConfig({
  site: SITE.origin,
  base: SITE.pathname,
  outDir: `dist${SITE.pathname}`,
  output: "static",
  build: { inlineStylesheets: "never" },
  trailingSlash: "always",
  compressHTML: true,
  markdown: { syntaxHighlight: "prism" },
  security: {
    csp: {
      directives: [
        "default-src 'none'",
        "base-uri 'self'",
        "connect-src 'self'",
        "font-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "img-src 'self' data:",
        "object-src 'none'",
      ],
      scriptDirective: { resources: [{ resource: "'self'", kind: "element" }] },
      styleDirective: {
        resources: [
          { resource: "'self'", kind: "element" },
          { resource: "'unsafe-inline'", kind: "attribute" },
        ],
      },
    },
  },
  integrations: [
    react(),
    starlight({
      title: "Workspace Sync",
      description: metadata.description,
      favicon: "/favicon.ico",
      disable404Route: true,
      customCss: ["@sarj/design/starlight.css", "./src/styles/global.css"],
      sidebar: SIDEBAR,
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/sarj-ai/workspace-sync",
        },
      ],
      pagefind: false,
      tableOfContents: false,
      credits: false,
      components: {
        Head: "./src/components/engineering-head.astro",
        Search: "./src/components/disabled-feature.astro",
        TableOfContents: "./src/components/disabled-feature.astro",
        MobileTableOfContents: "./src/components/disabled-feature.astro",
        PageTitle: "@sarj/design/PageAnchor.astro",
        SiteTitle: "./src/components/project-navigation.astro",
      },
    }),
    cloudflareArtifacts(
      pathToFileURL(`${resolve(import.meta.dirname, "dist")}/`),
      SITE,
    ),
  ],
});
