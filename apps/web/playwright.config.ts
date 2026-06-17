import { defineConfig } from "@playwright/test";
import path from "node:path";

const rootDir = path.resolve(__dirname, "../..");

export default defineConfig({
  testDir: "./tests",
  // The tests share a single API server and SQLite database, so run serially to
  // avoid write contention between concurrent baseline/eval runs.
  workers: 1,
  use: {
    baseURL: "http://localhost:3000",
  },
  webServer: [
    {
      command: "npm run dev:api",
      cwd: rootDir,
      url: "http://127.0.0.1:8000/health",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      command: "npm --workspace apps/web run start",
      cwd: rootDir,
      url: "http://127.0.0.1:3000",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
});
