import { defineConfig } from "@playwright/test";

// The role sweep (e2e/roles.spec.ts) against a real Palisade: e2e/setup.ts
// builds the binary, starts it on a temp DB and port 0, and signs in each
// role. Needs `make web` first; run with `make e2e`.
export default defineConfig({
  testDir: "e2e",
  globalSetup: "./e2e/setup.ts",
  timeout: 300_000,
  workers: 1,
  reporter: "list",
  use: { browserName: "chromium" },
});
