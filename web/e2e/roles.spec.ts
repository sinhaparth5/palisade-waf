import { expect, test, type Locator, type Page } from "@playwright/test";

// The role sweep (issue #357, was TestRolePageSweep): as a viewer and as an
// admin, open every page and press every button, menu item and switch, one
// dialog or menu deep, and fail on any 403. requireRole answers a write the
// role can't use with a 403 before the handler runs, so a control a role can
// see but not use shows up here, and so does a page that reads what the role
// can't. Writes the role may use do run, on the throwaway DB.

const pages = ["/", "/logs", "/services", "/ip-rules", "/geo-rules", "/certificates", "/threat-intel", "/waf-rules", "/settings", "/settings/pro"];
// Writes held back: they sign this browser out, or reach another server.
const held = /\/(logout|credentials|devices(\/.*)?|sync|test|purge|passkeys\/begin)$/;
const controls = "button:visible, [role^=menuitem]:visible";
const overlays = "[role=dialog]:visible, [role=alertdialog]:visible, [role=menu]:visible";

for (const role of ["viewer", "admin"]) {
  test.describe(role, () => {
    test.use({ baseURL: process.env.E2E_BASE, storageState: `${process.env.E2E_DIR}/${role}.json` });

    for (const path of pages) {
      test(path, async ({ page }) => {
        const failures: string[] = [];
        let last = "page load";
        page.on("response", (r) => {
          if (r.status() === 403) failures.push(`${r.request().method()} ${new URL(r.url()).pathname} (after ${last})`);
        });
        page.on("pageerror", (e) => failures.push(`page error: ${e.message} (after ${last})`));
        await page.route(
          (u) => held.test(u.pathname),
          (r) => (r.request().method() === "GET" ? r.continue() : r.abort()),
        );

        const url = `/admin${path}`;
        await page.goto(url);
        await page.waitForLoadState("networkidle");
        await expect(page).not.toHaveURL(/\/login/);
        await sweep(page, page.locator("main"), url, (n) => (last = n), 0);
        await page.waitForLoadState("networkidle");
        expect(failures).toEqual([]);
      });
    }
  });
}

async function sweep(page: Page, scope: Locator, url: string, note: (n: string) => void, depth: number) {
  const items = scope.locator(controls);
  const n = Math.min(await items.count(), 80);
  for (let i = 0; i < n; i++) {
    const item = items.nth(i);
    if (!(await item.isVisible()) || !(await item.isEnabled())) continue;
    const name = await item
      .evaluate((el) => ((el as HTMLElement).innerText || el.getAttribute("aria-label") || "").trim(), null, { timeout: 500 })
      .catch(() => null);
    // Gone (its dialog closed), or a dialog's way out: the action next to it matters.
    if (name === null || (depth > 0 && /^(cancel|close)$/i.test(name))) continue;
    note(name || `#${i}`);
    const open = await page.locator(overlays).count();
    if (await item.click({ timeout: 2000 }).then(() => false, () => true)) continue;
    await page.waitForTimeout(150);
    if (depth < 1 && (await page.locator(overlays).count()) > open) {
      await sweep(page, page.locator(overlays).last(), url, (m) => note(`${name || `#${i}`} › ${m}`), depth + 1);
    }
    if (depth === 0) {
      // Close whatever opened, and come back if a link or form left the page.
      for (let k = 0; k < 5 && (await page.locator(overlays).count()) > 0; k++) {
        await page.keyboard.press("Escape");
        await page.waitForTimeout(100);
      }
      if (new URL(page.url()).pathname !== url) await page.goto(url);
    }
  }
}
