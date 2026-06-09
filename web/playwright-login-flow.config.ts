import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "onyx-login-flow.spec.ts",
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: "http://10.2.48.90:3000",
    ignoreHTTPSErrors: true,
    headless: true,
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
        launchOptions: {
          args: ["--ignore-certificate-errors"],
        },
      },
    },
  ],
});
