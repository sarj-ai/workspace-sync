// Repository-owned Oxlint entrypoint. `oxlint.strict.mts` next to this file is SYNCED:
// `code-standards update` overwrites it. Put every repository-specific decision here.
// Later overrides win, so you can relax a rule, add a framework exemption, or scope one
// to a directory without forking the managed policy.
import { defineConfig } from "oxlint";

import { createConfig, ignorePatterns } from "./oxlint.strict.mts";

// Bun, Testing Library and Playwright are opt-in because their global test syntax overlaps
// other runners. To enable them, pass options to createConfig:
//   createConfig({
//     testFrameworks: ["vitest", "bun", "node", "testing-library", "playwright"],
//     playwrightTestFiles: ["tests/browser/**/*.spec.ts"],
//   })

const managed = createConfig();

export default defineConfig({
  extends: [managed],
  // Oxlint reads `settings` only from this root config.
  settings: managed.settings,
  ignorePatterns: [...ignorePatterns],
  overrides: [
    // Example: your router generates bracketed filenames that unicorn rejects.
    //
    // {
    //   files: ["src/routes/**/*.tsx"],
    //   rules: {
    //     "unicorn/filename-case": ["error", { cases: { kebabCase: true }, ignore: [String.raw`^\[`] }],
    //   },
    // },
  ],
});
