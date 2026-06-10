import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  timeout: 60000,
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  testMatch: /onyx-login-test\.spec\.ts/,
  outputDir: "output/playwright-login-test",
  use: {
    baseURL: "http://10.2.48.90:3000",
    trace: "on",
    ignoreHTTPSErrors: true,
    ...devices["Desktop Chrome"],
    viewport: { width: 1280, height: 720 },
  },
});
