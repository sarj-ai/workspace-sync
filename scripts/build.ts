import { execFileSync } from "node:child_process";
import { rm } from "node:fs/promises";

// A clean emit prevents removed modules and stale declarations from entering releases.
await rm(new URL("../dist/", import.meta.url), {
  recursive: true,
  force: true,
});
execFileSync("pnpm", ["exec", "tsrs", "-p", "tsconfig.build.json"], {
  cwd: new URL("../", import.meta.url),
  stdio: "inherit",
});
