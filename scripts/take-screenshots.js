const { chromium } = require('playwright');
const path = require('path');

const BASE = 'https://admin.crelvo.dev';
const BASIC_USER = 'admin';
const BASIC_PASS = 'appmanager2024';
const LOGIN_USER = 'admin';
const LOGIN_PASS = 'appmanager2024';
const OUT = path.join(__dirname, '..', 'screenshots');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    httpCredentials: { username: BASIC_USER, password: BASIC_PASS },
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();

  // Login
  console.log('[1/7] Logging in...');
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('input[name="username"]', LOGIN_USER);
  await page.fill('input[name="password"]', LOGIN_PASS);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(4000);

  // Dismiss morning briefing if it auto-opened
  console.log('[2/7] Dismissing briefing, capturing dashboard overview...');
  const dismissBtn = page.locator('button:has-text("Dismiss")').first();
  if (await dismissBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await dismissBtn.click();
    await page.waitForTimeout(1500);
  }
  // Scroll to top to show the clean dashboard
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(OUT, '01-dashboard-overview.png'), fullPage: false });

  // 2. Marketing Manager - Revenue tab
  console.log('[3/7] Marketing Revenue tab...');
  await page.keyboard.press('m');
  await page.waitForTimeout(1500);
  // Click Revenue tab
  const revenueTab = page.locator('text=Revenue').first();
  if (await revenueTab.isVisible({ timeout: 2000 }).catch(() => false)) {
    await revenueTab.click();
    await page.waitForTimeout(2000);
  }
  await page.screenshot({ path: path.join(OUT, '02-marketing-revenue.png'), fullPage: false });

  // 3. Command palette
  console.log('[4/7] Command palette...');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(300);
  await page.keyboard.press('Control+k');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(OUT, '03-command-palette.png'), fullPage: false });

  // 4. Morning briefing (reopen it)
  console.log('[5/7] Morning briefing...');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(300);
  await page.keyboard.press('d');
  await page.waitForTimeout(4000);
  await page.screenshot({ path: path.join(OUT, '04-morning-briefing.png'), fullPage: false });

  // 5. Healing panel
  console.log('[6/7] Healing panel...');
  // Dismiss briefing first
  const dismissBtn2 = page.locator('button:has-text("Dismiss")').first();
  if (await dismissBtn2.isVisible({ timeout: 2000 }).catch(() => false)) {
    await dismissBtn2.click();
    await page.waitForTimeout(1000);
  }
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(300);
  await page.keyboard.press('h');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT, '05-healing-panel.png'), fullPage: false });

  // 6. Settings panel - click the Settings button in the top bar
  console.log('[7/7] Settings panel...');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(500);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(300);
  const settingsBtn = page.locator('button:has-text("Settings")').first();
  if (await settingsBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await settingsBtn.click();
    await page.waitForTimeout(2000);
  }
  await page.screenshot({ path: path.join(OUT, '06-settings.png'), fullPage: false });

  await browser.close();
  console.log(`Done! Screenshots saved to ${OUT}`);
})();
