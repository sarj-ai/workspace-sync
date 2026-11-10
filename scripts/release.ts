import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import manifest from "../package.json" with { type: "json" };
import build from "../tsconfig.build.json" with { type: "json" };

const root = path.resolve(import.meta.dirname, "..");
const read = (file: string): Promise<string> =>
  readFile(path.join(root, file), "utf8");

async function checkDistribution() {
  const sourceFiles = await readdir(path.join(root, "src"), {
    recursive: true,
  });
  const sourcePaths = sourceFiles
    .filter((file) => file.endsWith(".ts"))
    .toSorted();
  const sources = new Map<string, string>(
    await Promise.all(
      sourcePaths.map(
        async (file) => [file, await read(`src/${file}`)] as const,
      ),
    ),
  );
  const code = sources.values().toArray().join("\n");
  const textualSources = sources
    .entries()
    .toArray()
    .filter(([file]) => file !== "org-sync/org-chart-fonts.ts");
  const hygieneFiles = new Map<string, string>(
    sources
      .entries()
      .toArray()
      .map(([file, content]) => [`src/${file}`, content] as const),
  );
  await Promise.all(
    ["test", "examples"].map(async (directory) => {
      const files = await readdir(path.join(root, directory), {
        recursive: true,
      });
      await Promise.all(
        files.map(async (file) => {
          if (!/\.(?:ts|json)$/u.test(file)) return;
          hygieneFiles.set(
            `${directory}/${file}`,
            await read(`${directory}/${file}`),
          );
        }),
      );
    }),
  );
  const policy = await read("pnpm-workspace.yaml");
  const lock = await read("pnpm-lock.yaml");
  const checks: {
    pass: number;
    name: string;
    assertion: () => void | Promise<void>;
  }[] = [];

  function check(name: string, assertion: () => void | Promise<void>): void {
    checks.push({ pass: checks.length + 1, name, assertion });
  }

  check("Credential material", () =>
    assert.doesNotMatch(
      code,
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|["'](?:xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9]{30,})["']/u,
    ),
  );
  check("Tenant email separation", () => {
    for (const [file, content] of hygieneFiles)
      assert.doesNotMatch(content, /[A-Za-z0-9._%+-]+@sarj\.ai/iu, file);
  });
  check("Immutable tenant identifier separation", () => {
    for (const [file, content] of textualSources)
      assert.doesNotMatch(
        content,
        /['"](?:\d{20,22}|[TCUS]0[A-Z0-9]{8,})['"]/u,
        file,
      );
  });
  check("Host filesystem separation", () =>
    assert.doesNotMatch(code, /\/home\/|\/Users\/|code\/worktrees/u),
  );
  check("Private workspace dependency separation", () =>
    assert.doesNotMatch(code, /from ['"]@sarj-ai\//u),
  );
  check("Local import containment and resolution", () => {
    for (const [file, content] of sources) {
      for (const match of content.matchAll(
        /(?:from\s*|import\s*)['"](\.[^'"]+)['"]/gu,
      )) {
        assert.ok(match[1]);
        const target = path.posix.normalize(
          path.posix.join(path.posix.dirname(file), match[1]),
        );
        assert.ok(
          !target.startsWith("../") && sources.has(target),
          `${file}: ${target}`,
        );
      }
    }
  });
  check("Exact runtime dependency versions", () => {
    for (const version of Object.values(manifest.dependencies))
      assert.match(
        version,
        /^(?:npm:(?:@[^/]+\/)?[^@]+@)?\d+\.\d+\.\d+(?:-[\w.-]+)?$/u,
      );
  });
  check("Exact development dependency versions", () => {
    for (const version of Object.values(manifest.devDependencies))
      assert.match(
        version,
        /^(?:npm:(?:@[^/]+\/)?[^@]+@)?\d+\.\d+\.\d+(?:-[\w.-]+)?$/u,
      );
  });
  check("Code and font license notices", async () => {
    assert.equal(manifest.license, "MIT");
    assert.match(await read("LICENSE"), /MIT License/u);
    assert.match(
      await read("LICENSES/Nunito-OFL-1.1.txt"),
      /SIL OPEN FONT LICENSE Version 1\.1/u,
    );
    const license = await read("LICENSES/Nunito-OFL-1.1.txt");
    const copyright = license.split("\n")[0] ?? "";
    assert.ok(copyright.startsWith("Copyright"));
    assert.match(copyright, /^[\x20-\x7E]+$/u);
    // Font name records store this ASCII notice as UTF-16BE.
    const encodedCopyright = Array.from(
      copyright,
      (character) => `\0${character}`,
    ).join("");
    const fonts = await read("src/org-sync/org-chart-fonts.ts");
    const data = fonts.matchAll(/['"]([A-Za-z0-9+/=]{1000,})['"]/gu).toArray();
    assert.equal(data.length, 2);
    for (const match of data) {
      assert.ok(match[1]);
      assert.ok(atob(match[1]).includes(encodedCopyright));
    }
  });
  check("Consumer lifecycle hooks", () => {
    for (const name of ["preinstall", "install", "postinstall", "prepare"])
      assert.equal(Object.hasOwn(manifest.scripts, name), false);
  });
  check("npm publication remains disabled", () =>
    assert.equal(manifest.private, true),
  );
  check("Package content allowlist", () =>
    assert.deepEqual(manifest.files, [
      "dist",
      "README.md",
      "LICENSE",
      "SECURITY.md",
      "THIRD_PARTY_NOTICES.md",
      "LICENSES",
    ]),
  );
  check("Source-map disclosure", () => {
    assert.equal(build.compilerOptions.sourceMap, false);
    assert.equal(build.compilerOptions.declarationMap, false);
  });
  check("Independent compiled exports", async () => {
    assert.equal(manifest.exports["."].import, "./dist/configuration.js");
    const files = await readdir(path.join(root, "dist"));
    assert.ok(files.includes("configuration.js"));
    await import(
      pathToFileURL(path.join(root, manifest.exports["."].import)).href
    );
  });
  check("Source and test publication boundary", () =>
    assert.ok(
      !manifest.files.some((file) => /^(src|test|examples|\.env)/u.test(file)),
    ),
  );
  check("Lockfile integrity records", () =>
    assert.match(lock, /integrity: sha512-/u),
  );
  check("Exotic dependency transport boundary", () => {
    assert.match(policy, /blockExoticSubdeps: true/u);
    assert.doesNotMatch(
      lock,
      /tarball: (?:http:|git\+|file:)|gitCommit:|gitRepo:/u,
    );
  });
  check("Dependency lifecycle execution", () => {
    assert.match(policy, /ignoreScripts: true/u);
    assert.match(policy, /strictDepBuilds: true/u);
  });
  check("Release-age and provenance downgrade controls", () => {
    assert.match(policy, /minimumReleaseAge: 20160/u);
    assert.match(policy, /minimumReleaseAgeStrict: true/u);
    assert.match(policy, /trustPolicy: no-downgrade/u);
  });
  check("CI action pins and token permissions", async () => {
    const workflow = await read(".github/workflows/ci.yml");
    const uses = workflow.matchAll(/uses:\s+([^\s#]+)/gu).toArray();
    assert.ok(uses.length > 0);
    for (const use of uses) {
      assert.ok(use[1]);
      assert.match(use[1], /@[a-f0-9]{40}$/u);
    }
    assert.match(workflow, /contents: read/u);
    assert.doesNotMatch(
      workflow,
      /pull_request_target|contents: write|id-token: write/u,
    );
  });
  const results = await Promise.all(
    checks.map(async (entry) => {
      try {
        await entry.assertion();
        return { pass: entry.pass, name: entry.name, result: "passed" };
      } catch (error) {
        return {
          pass: entry.pass,
          name: entry.name,
          result: "failed",
          error: error instanceof Error ? error.message : String(error),
        };
      }
    }),
  );
  const sourceSha256 = hash(
    "sha256",
    sources
      .entries()
      .toArray()
      .map(([file, content]) => `${file}\0${content}\0`)
      .join(""),
  );
  await mkdir(path.join(root, ".security-review"), { recursive: true });
  await writeFile(
    path.join(root, ".security-review/results.json"),
    `${JSON.stringify({ sourceSha256, results }, null, 2)}\n`,
  );
  for (const result of results)
    process.stdout.write(
      `${String(result.pass).padStart(2, "0")} ${result.result}: ${result.name}\n`,
    );
  assert.ok(
    results.every((result) => result.result === "passed"),
    "Security review guards failed; see .security-review/results.json",
  );
}

async function smoke(): Promise<void> {
  const files = await readdir(path.join(root, ".security-review"));
  const archives = files.filter((file) => file.endsWith(".tgz"));
  assert.equal(archives.length, 1);
  const archive = archives[0];
  assert.ok(archive);
  const temporary = await mkdtemp(path.join(root, ".security-review/smoke-"));
  try {
    const archivePath = path.join(root, ".security-review", archive);
    const entries = execFileSync("tar", ["-tzf", archivePath], {
      encoding: "utf8",
    })
      .trim()
      .split("\n");
    for (const entry of entries) {
      assert.ok(
        entry.startsWith("package/") && !entry.split("/").includes(".."),
      );
    }
    execFileSync("tar", ["-xzf", archivePath, "-C", temporary]);
    const packagedRoot = pathToFileURL(
      path.join(temporary, "package") + path.sep,
    );
    const metadata: unknown = JSON.parse(
      await readFile(new URL("package.json", packagedRoot), "utf8"),
    );
    // pnpm omits package-manager metadata and packing hooks from the consumer manifest.
    const {
      packageManager: _packageManager,
      scripts,
      ...publishedManifest
    } = manifest;
    const { prepack: _prepack, ...consumerScripts } = scripts;
    const expected: unknown = {
      ...publishedManifest,
      scripts: consumerScripts,
    };
    assert.deepEqual(metadata, expected);
    const { z } = await import("zod");
    const configuration: unknown = await import(
      new URL("dist/configuration.js", packagedRoot).href
    );
    const lifecycle: unknown = await import(
      new URL("dist/google-workspace/user-lifecycle.js", packagedRoot).href
    );
    const authority: unknown = await import(
      new URL("dist/org-sync/google-directory-authority.js", packagedRoot).href
    );
    const { getWorkspaceSyncPolicy } = z
      .object({
        getWorkspaceSyncPolicy: z.function({ input: [], output: z.unknown() }),
      })
      .parse(configuration);
    const { isActiveGoogleUser } = z
      .object({
        isActiveGoogleUser: z.function({
          input: [z.record(z.string(), z.unknown())],
          output: z.boolean(),
        }),
      })
      .parse(lifecycle);
    const { mergeGoogleDirectoryAuthority } = z
      .object({
        mergeGoogleDirectoryAuthority: z.function({
          input: [z.array(z.unknown()), z.array(z.unknown())],
          output: z.array(z.unknown()),
        }),
      })
      .parse(authority);
    assert.equal(isActiveGoogleUser({ suspended: false }), true);
    assert.equal(isActiveGoogleUser({ suspended: true }), false);
    assert.equal(
      isActiveGoogleUser({ deletionTime: "2026-01-01T00:00:00Z" }),
      false,
    );
    assert.throws(
      () => getWorkspaceSyncPolicy(),
      /workspace_sync_policy_not_configured/u,
    );
    assert.deepEqual(mergeGoogleDirectoryAuthority([], []), []);
    for (const target of Object.values(manifest.exports)) {
      // eslint-disable-next-line @sarj/no-runtime-typeof -- Package export maps admit both path strings and descriptor objects.
      if (typeof target === "string") continue;
      // eslint-disable-next-line no-await-in-loop -- Verify each archive entry and module without overlapping module initialization.
      await readFile(new URL(target.types, packagedRoot));
      // eslint-disable-next-line no-await-in-loop -- Imports remain sequential so fail-closed initialization is observable.
      await import(new URL(target.import, packagedRoot).href);
    }
    assert.throws(
      () => getWorkspaceSyncPolicy(),
      /workspace_sync_policy_not_configured/u,
    );
    process.stdout.write(
      "Release archive imports, declarations and fail-closed defaults passed.\n",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function qualify() {
  const sourceHead = git("rev-parse", "HEAD");
  assert.equal(sourceHead, process.env["SOURCE_HEAD"]);
  assert.equal(git("status", "--porcelain"), "");
  const files = await readdir(".security-review");
  const archives = files.filter((file) => file.endsWith(".tgz"));
  assert.equal(archives.length, 1);
  const archive = archives[0];
  assert.ok(archive);
  const archiveSha256 = hash(
    "sha256",
    await readFile(`.security-review/${archive}`),
  );
  const sourceArchive = "workspace-sync-source.tar.gz";
  const sourceArchiveSha256 = hash(
    "sha256",
    await readFile(`.security-review/${sourceArchive}`),
  );
  const [primaryNodeText, pnpmText] = await Promise.all([
    readFile(".security-review/primary-node.txt", "utf8"),
    readFile(".security-review/pnpm-version.txt", "utf8"),
  ]);
  const qualification = {
    sourceHead,
    sourceTree: git("rev-parse", "HEAD^{tree}"),
    runId: process.env["GITHUB_RUN_ID"],
    runAttempt: process.env["GITHUB_RUN_ATTEMPT"],
    primaryNode: primaryNodeText.trim(),
    compatibilityNode: process.version,
    pnpm: pnpmText.trim(),
    archive,
    archiveSha256,
    sourceArchive,
    sourceArchiveSha256,
    // Protected main separately requires exact-head Standards and commit policy.
    applicationVerificationExit: 0,
  };
  await writeFile(
    ".security-review/qualification.json",
    `${JSON.stringify(qualification, null, 2)}\n`,
  );
}

const git = (...args: string[]): string =>
  execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();

async function scanSecrets(targets: readonly string[]) {
  const temporary = await mkdtemp(
    path.join(tmpdir(), "workspace-sync-secrets-"),
  );
  try {
    const config = path.join(temporary, "config.toml");
    const ignore = path.join(temporary, "empty.gitleaksignore");
    await writeFile(config, "[extend]\nuseDefault = true\n", { mode: 0o600 });
    await writeFile(ignore, "", { mode: 0o600 });
    const scopes = targets.length
      ? targets.map((target) => ["dir", target])
      : [["git", ".", "--log-opts=--all --full-history"]];
    if (!targets.length) {
      const objects = execFileSync(
        "git",
        ["rev-list", "--objects", "--all", "--missing=print"],
        { cwd: root, encoding: "utf8" },
      );
      assert.doesNotMatch(
        objects,
        /^\?/mu,
        "Secret scanning requires complete Git objects",
      );
    }
    for (const scope of scopes) {
      try {
        execFileSync(
          "mise",
          [
            "--no-config",
            "--no-env",
            "--no-hooks",
            "exec",
            "aqua:gitleaks/gitleaks@8.30.1",
            "--",
            "gitleaks",
            ...scope,
            "--config",
            config,
            "--gitleaks-ignore-path",
            ignore,
            "--redact=100",
            "--ignore-gitleaks-allow",
            "--max-archive-depth=3",
            "--max-decode-depth=5",
            "--no-banner",
            "--no-color",
            "--log-level=error",
          ],
          { cwd: root, stdio: ["ignore", "pipe", "pipe"], timeout: 300_000 },
        );
      } catch {
        throw new Error(
          "Secret scan failed. Inspect the candidate with a private local scan.",
        );
      }
    }
    process.stdout.write("No secrets detected.\n");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

switch (process.argv[2] ?? "") {
  case "repository-standards":
    execFileSync(
      "uvx",
      [
        "--no-config",
        "--isolated",
        "--python",
        "3.14",
        "--from",
        "repo-standards==6.22.3",
        "repo-standards",
        "check",
        ".",
        "--staged",
        "--mode",
        "strict",
      ],
      { cwd: root, stdio: "inherit" },
    );
    break;
  case "check":
    await checkDistribution();
    break;
  case "smoke":
    await smoke();
    break;
  case "qualify":
    await qualify();
    break;
  case "scan":
    await scanSecrets(process.argv.slice(3));
    break;
  default:
    throw new Error(
      "Usage: node scripts/release.ts check|repository-standards|smoke|qualify|scan [paths...]",
    );
}
