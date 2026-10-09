import { defineConfig, devices } from "@playwright/test";

// The mocked tier of agntcy/shadi#125: the real frontend on Vite with the
// Tauri backend replaced by canned answers (see e2e/tauri.ts), so it runs on
// any runner with no SLIM node, sandbox or keychain. PW_CHANNEL picks an
// installed browser (e.g. `msedge`) instead of Playwright's own Chromium.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://localhost:1420",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], channel: process.env.PW_CHANNEL },
    },
  ],
  webServer: {
    command: "pnpm exec vite --port 1420 --strictPort",
    url: "http://localhost:1420",
    reuseExistingServer: !process.env.CI,
  },
});
