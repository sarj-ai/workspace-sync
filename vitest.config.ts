import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    setupFiles: ["./test/setup.ts"],
    maxWorkers: 2,
    fileParallelism: false,
    restoreMocks: true,
  },
});
