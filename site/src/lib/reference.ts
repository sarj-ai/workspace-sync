import { root } from "astro:config/server";

import metadata from "../../../package.json" with { type: "json" };
import { deriveDocumentationReference } from "../../../scripts/derive-documentation-reference.ts";

export const REFERENCE = await deriveDocumentationReference(
  new URL("../", root),
);
export { SIDEBAR } from "./sidebar.ts";
export const siteHref = (path = ""): string =>
  new URL(path, metadata.homepage).pathname;
