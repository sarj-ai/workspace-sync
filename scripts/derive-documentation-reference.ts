import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { z } from "zod";

import { profilePlan } from "../examples/profile-plan.ts";
import metadata from "../package.json" with { type: "json" };
import { WorkspaceSyncPolicySchema } from "../src/configuration.ts";

export async function deriveDocumentationReference(root: URL) {
  const repository = metadata.repository.url
    .replace(/^git\+/u, "")
    .replace(/\.git$/u, "");
  const archiveName = `${metadata.name.replace(/^@/u, "").replaceAll("/", "-")}-${metadata.version}.tgz`;
  const install = `pnpm add ${repository}/releases/download/v${metadata.version}/${archiveName} zod@${metadata.dependencies.zod}`;
  const read = (path: string): Promise<string> =>
    readFile(new URL(path, root), "utf8");
  const source = await read("src/configuration.ts");
  const overview =
    /^\/\*\*\n([\s\S]*?)\*\//u
      .exec(source)?.[1]
      ?.split("\n")
      .map((line) => line.replace(/^ \* ?/u, "").trimEnd())
      .join("\n")
      .trim() ?? "";
  assert.ok(overview, "The policy contract must document its trust boundary");
  const policyExample = await read("examples/policy.example.json");
  WorkspaceSyncPolicySchema.parse(JSON.parse(policyExample));
  const publicExample = async (path: string): Promise<string> => {
    const exampleSource = await read(path);
    return exampleSource
      .replaceAll(/^[ \t]*\/\/ eslint-disable-next-line [^\n]*\n/gmu, "")
      .replaceAll("../src/configuration.ts", () => metadata.name)
      .replaceAll("../src/", () => `${metadata.name}/`)
      .replaceAll(/\.ts(['"])/gu, "$1")
      .trim();
  };
  const example = await publicExample("examples/audit-directory.ts");
  const planExample = await publicExample("examples/plan-and-apply.ts");
  const policySchema = z.toJSONSchema(WorkspaceSyncPolicySchema, {
    io: "input",
  });
  const modules = await Promise.all(
    Object.entries(metadata.exports).flatMap(([name, target]) => {
      // eslint-disable-next-line @sarj/no-runtime-typeof -- Export maps admit path strings and descriptor objects.
      if (typeof target === "string") return [];
      assert.match(target.types, /^\.\/dist\/[\w/-]+\.d\.ts$/u);
      assert.match(target.import, /^\.\/dist\/[\w/-]+\.js$/u);
      const module = target.import.slice("./dist/".length, -".js".length);
      return [
        (async () => ({
          name:
            name === "." ? metadata.name : `${metadata.name}/${name.slice(2)}`,
          module,
          declaration: await read(target.types),
        }))(),
      ];
    }),
  );
  const development =
    "mise install\nmise exec -- pnpm install --frozen-lockfile\nmise exec -- pnpm verify";

  assert.deepEqual(
    profilePlan.errors,
    [],
    "The documentation preview must be a valid plan",
  );
  const preview = profilePlan.profiles[0];
  assert.ok(preview, "The documentation preview must contain a profile");

  return Object.freeze({
    version: metadata.version,
    node: metadata.engines.node,
    description: metadata.description,
    repository,
    install,
    example,
    planExample,
    policyExample,
    policySchema,
    development,
    modules,
    preview,
    security: overview.split(/\n\s*\n/u).slice(1),
  });
}
