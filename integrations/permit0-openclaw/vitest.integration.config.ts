import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["__tests__/integration/**/*.test.ts"],
    environment: "node",
    globals: false,
    // The setup spawns a real binary; give each test plenty of headroom.
    testTimeout: 20_000,
    hookTimeout: 30_000,
  },
});
