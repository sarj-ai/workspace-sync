import metadata from "../../../package.json" with { type: "json" };

export { default as REFERENCE } from "../../generated/reference.ts";
export { SIDEBAR } from "./sidebar.ts";
export const siteHref = (path = ""): string =>
  new URL(path, metadata.homepage).pathname;
