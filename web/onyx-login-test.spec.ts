import { test, expect } from "@playwright/test";

const BASE_URL = "http://10.2.48.90:3000";
const KEYCLOAK_BASE = "http://10.2.48.90:8082";
const TEST_USERNAME = "testuser";
const TEST_PASSWORD = "TestPass123!";

test.describe("Onyx Full Login Flow with Enterprise Verification", () => {
  test("Complete OIDC login via Keycloak and verify enterprise features", async ({ browser }) => {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    const networkLog: { status: number; url: string; location?: string }[] = [];
    page.on("response", async (resp) => {
      const url = resp.url();
      const status = resp.status();
      if ([301, 302, 303, 307, 308].includes(status)) {
        networkLog.push({ status, url: url.substring(0, 150), location: resp.headers()["location"]?.substring(0, 150) });
      }
    });

    // ============================================================
    // PHASE 1: Navigate to Onyx, intercept Keycloak -> Feishu redirect
    // ============================================================
    console.log("\n========== PHASE 1: Start OIDC flow ==========");

    // Navigate to Onyx. The redirect chain is:
    // Onyx -> Keycloak -> Feishu broker -> Feishu SSO
    // We want to stop at Keycloak and fill the direct login form.

    // Use route interception to block the Feishu redirect
    // Keycloak does a 303 redirect to /broker/feishu-broker/login
    // Then another 303 to the feishu-broker service
    // We'll intercept the feishu-broker redirect and stay on Keycloak

    await page.route("**/broker/feishu-broker/**", async (route) => {
      console.log("INTERCEPTED Feishu broker redirect:", route.request().url());
      // Abort this route - we don't want to go to Feishu
      await route.abort();
    });

    // Navigate to Onyx
    await page.goto(BASE_URL, { waitUntil: "domcontentloaded", timeout: 30000 });

    // Wait for Keycloak page
    await page.waitForURL(/8082|18080|feishu|lark|about:blank/, { timeout: 30000 }).catch(() => {});
    console.log("URL after navigation:", page.url());

    // ============================================================
    // PHASE 2: Keycloak direct login
    // ============================================================
    console.log("\n========== PHASE 2: Keycloak direct login ==========");

    // Since we intercepted the Feishu redirect, we might be on the Keycloak error page
    // or the browser might be showing about:blank because the route was aborted
    //
    // Better approach: use Keycloak's direct login form by navigating to it
    // with a special parameter that prevents the IdP redirect

    // Clear the route interception
    await page.unroute("**/broker/feishu-broker/**");

    // Navigate to Keycloak's auth endpoint with kc_idp_hint= to prevent Feishu redirect
    // Actually Keycloak doesn't support empty kc_idp_hint to disable redirect
    //
    // Better: just navigate to Keycloak, let it redirect to Feishu broker,
    // but intercept the feishu-broker authorize call and redirect back to
    // Keycloak's login form instead

    // Restart with a fresh approach: navigate to the Keycloak login form directly
    // Keycloak stores the auth session in a cookie, so we need the same session

    // Alternative: Use the Onyx authorize endpoint to get a valid Keycloak session
    // then immediately navigate to Keycloak's login page
    const authorizeResp = await page.request.get(`${BASE_URL}/api/auth/oidc/authorize?redirect=true`, {
      maxRedirects: 0,
    });
    const keycloakUrl = authorizeResp.headers()["location"];
    console.log("Keycloak auth URL from Onyx:", keycloakUrl?.substring(0, 150));

    if (!keycloakUrl) {
      // Try to extract from redirect chain
      console.log("No direct redirect, trying alternate approach");
      console.log("Response status:", authorizeResp.status());
      console.log("Headers:", JSON.stringify(authorizeResp.headers()));
    }

    // Navigate to the Keycloak auth URL with route interception to block Feishu
    let keycloakLoginPage = false;

    await page.route("**/18080/**", async (route) => {
      console.log("BLOCKED feishu-broker redirect, staying on Keycloak");
      // Respond with a simple page that does nothing
      await route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<html><body>Blocked Feishu redirect</body></html>",
      });
    });

    if (keycloakUrl) {
      console.log("Navigating to Keycloak auth URL...");
      await page.goto(keycloakUrl, { waitUntil: "domcontentloaded", timeout: 15000 }).catch(() => {});
      console.log("After Keycloak navigation:", page.url());

      // Check if we're on Keycloak login form
      const hasLoginForm = await page.$("#username");
      if (hasLoginForm) {
        keycloakLoginPage = true;
        console.log("SUCCESS: Keycloak login form is visible!");
      } else {
        console.log("No login form. Trying to find alternative...");
        const body = await page.textContent("body").catch(() => "empty");
        console.log("Page content:", body?.substring(0, 300));
      }
    }

    // If the Feishu intercept worked and we're on the fulfilled page,
    // go back to Keycloak's login form
    if (!keycloakLoginPage) {
      console.log("Trying goBack to reach Keycloak...");
      await page.goBack({ waitUntil: "domcontentloaded", timeout: 10000 }).catch(() => {});
      console.log("After goBack:", page.url());

      const hasLoginForm = await page.$("#username");
      if (hasLoginForm) {
        keycloakLoginPage = true;
        console.log("Found Keycloak login form after goBack!");
      }
    }

    // If still no login form, try direct Keycloak URL construction
    if (!keycloakLoginPage) {
      console.log("Trying direct Keycloak URL with tab_id...");
      // Navigate to Keycloak realm login
      await page.goto(`${KEYCLOAK_BASE}/realms/hello-world/protocol/openid-connect/auth?client_id=onyx&redirect_uri=${encodeURIComponent(BASE_URL + "/auth/oidc/callback")}&response_type=code&scope=openid`, {
        waitUntil: "domcontentloaded",
        timeout: 15000,
      }).catch(() => {});
      console.log("Direct Keycloak URL:", page.url());

      const hasLoginForm = await page.$("#username");
      if (hasLoginForm) {
        keycloakLoginPage = true;
        console.log("Found Keycloak login form via direct URL!");
      } else {
        const body = await page.textContent("body").catch(() => "empty");
        console.log("Page:", body?.substring(0, 300));
      }
    }

    await page.unroute("**/18080/**");

    if (!keycloakLoginPage) {
      console.log("\nCannot reach Keycloak login form - Feishu IdP auto-redirect is enforced");
      console.log("This means the login flow is: Onyx -> Keycloak -> Feishu (no fallback to direct login)");
      console.log("The enterprise features cannot be tested via browser automation without Feishu credentials");

      // Use API approach instead
      console.log("\n========== FALLBACK: API-based session creation ==========");

      // Get a token from Keycloak
      const tokenResp = await page.request.post(
        `${KEYCLOAK_BASE}/realms/hello-world/protocol/openid-connect/token`,
        {
          form: {
            client_id: "onyx",
            client_secret: "MzvHz3ApQCGZAz7CophVWctK0fyVP248",
            username: TEST_USERNAME,
            password: TEST_PASSWORD,
            grant_type: "password",
            scope: "openid",
          },
        }
      );

      if (tokenResp.ok()) {
        const tokens = await tokenResp.json();
        console.log("Got Keycloak token for testuser");

        // Simulate what the OIDC callback does:
        // 1. Call Onyx's authorize endpoint to get a valid state/session
        // 2. Then call the callback endpoint with the token
        //
        // Since this is complex, let's just check what the /settings API returns
        // when called with proper auth

        // The Onyx backend validates the session via the fastapiusersauth cookie
        // We need to get that cookie somehow

        // Check if there's an API key or token-based auth
        const meResp = await page.request.get(`${BASE_URL}/api/me`, {
          headers: {
            "Authorization": `Bearer ${tokens.access_token}`,
          },
        });
        console.log("/me with Bearer token:", meResp.status());
        if (meResp.ok()) {
          const me = await meResp.json();
          console.log("User:", JSON.stringify(me, null, 2));
        }

        // Check settings
        const settingsResp = await page.request.get(`${BASE_URL}/api/settings`, {
          headers: {
            "Authorization": `Bearer ${tokens.access_token}`,
          },
        });
        console.log("/settings with Bearer token:", settingsResp.status());
        if (settingsResp.ok()) {
          const settings = await settingsResp.json();
          console.log("Tier:", settings.tier);
          console.log("Application status:", settings.application_status);
        }
      }

      await context.close();
      return;
    }

    // ============================================================
    // PHASE 3: Fill Keycloak form and submit
    // ============================================================
    console.log("\n========== PHASE 3: Submit Keycloak login ==========");

    await page.fill("#username", TEST_USERNAME);
    await page.fill("#password", TEST_PASSWORD);
    console.log("Filled credentials for:", TEST_USERNAME);

    // Block Feishu redirect during callback too
    await page.route("**/18080/**", async (route) => {
      await route.fulfill({ status: 200, contentType: "text/html", body: "<html><body>Blocked</body></html>" });
    });

    // Submit and wait for the OIDC callback
    await Promise.all([
      page.waitForURL(/auth\/oidc\/callback|3000/, { timeout: 30000 }).catch(() => {}),
      page.click("#kc-login"),
    ]);

    console.log("After Keycloak login, URL:", page.url());
    await page.unroute("**/18080/**");

    // Wait for the full callback processing
    await page.waitForLoadState("networkidle", { timeout: 30000 }).catch(() => {});
    console.log("After callback, URL:", page.url());

    // ============================================================
    // PHASE 4: Verify login and enterprise features
    // ============================================================
    console.log("\n========== PHASE 4: Verify login and enterprise ==========");

    const meResp = await page.request.get(`${BASE_URL}/api/me`);
    console.log("/me status:", meResp.status());
    if (meResp.ok()) {
      const me = await meResp.json();
      console.log("Logged in user:", JSON.stringify(me, null, 2));
    }

    const settingsResp = await page.request.get(`${BASE_URL}/api/settings`);
    console.log("/settings status:", settingsResp.status());
    if (settingsResp.ok()) {
      const settings = await settingsResp.json();
      console.log("Settings:");
      console.log("  tier:", settings.tier);
      console.log("  application_status:", settings.application_status);
      console.log("  disable_anonymous_chat:", settings.disable_anonymous_chat);

      // Check enterprise/EE features
      console.log("\nEnterprise feature checks:");
      console.log("  Tier is enterprise/business:", ["enterprise", "business"].includes(settings.tier));
    }

    // Check admin user-group endpoint (the feature user said is disabled)
    const userGroupResp = await page.request.get(`${BASE_URL}/api/manage/admin/user-group`);
    console.log("/manage/admin/user-group status:", userGroupResp.status());
    if (userGroupResp.ok()) {
      const groups = await userGroupResp.json();
      console.log("User groups:", JSON.stringify(groups, null, 2));
    } else {
      const errText = await userGroupResp.text().catch(() => "");
      console.log("User group error:", errText.substring(0, 200));
    }

    // Print redirect chain
    console.log("\n========== Redirect chain ==========");
    networkLog.forEach((r, i) => {
      console.log(`  ${i + 1}. [${r.status}] ${r.url}`);
      if (r.location) console.log(`     -> ${r.location}`);
    });

    await context.close();
  });
});
