import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm } from "node:fs/promises";
import path from "node:path";

import build from "../tsconfig.build.json" with { type: "json" };

const root = path.resolve(import.meta.dirname, "..");
assert.equal(build.compilerOptions.outDir, "dist");

// A clean emit prevents removed modules and stale declarations from entering releases.
await rm(path.join(root, build.compilerOptions.outDir), {
  recursive: true,
  force: true,
});
execFileSync("pnpm", ["exec", "tsrs", "-p", "tsconfig.build.json"], {
  cwd: root,
  stdio: "inherit",
});
