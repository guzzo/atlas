import { chromium } from '@playwright/test';
import { strict as assert } from 'node:assert';
import { mkdir } from 'node:fs/promises';
const browser = await chromium.launch({ headless: true });
try {
  await mkdir('.local/reports', { recursive: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } }),
    errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(msg.text());
  });
  await page.goto(process.env.DASHBOARD_URL ?? 'http://127.0.0.1:8080');
  await page.getByText('Services connected', { exact: true }).waitFor();
  assert.equal(await page.locator('#org-count').textContent(), '2');
  await page.locator('details').first().locator('summary').click();
  assert.ok((await page.locator('details[open] pre').textContent())?.includes('signature'));
  await page.locator('details[open] summary').click();
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
  await page.screenshot({ path: '.local/reports/dashboard-desktop.png', fullPage: true });
  await page.getByRole('button', { name: 'Denials', exact: true }).click();
  assert.ok((await page.locator('#receipts-list').textContent())?.includes('denial'));
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  await page.screenshot({ path: '.local/reports/dashboard-mobile.png', fullPage: true });
  assert.deepEqual(errors, []);
  console.log('PASS  desktop/mobile dashboard, live data, receipt expansion and filters');
} finally {
  await browser.close();
}
