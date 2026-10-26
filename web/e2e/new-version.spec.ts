// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// A tab left open across an update: the app notices that the server has a newer build of its pages (SvelteKit's
// /_app/version.json no longer matches the build the tab loaded), says so, and loads the new build in full on the
// next move to another page. Here the browser answers version.json itself with a different build.
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

// A mark on the window that only a full page load clears.
const mark = (page: Page) => page.evaluate(() => ((window as unknown as { mark?: boolean }).mark = true));
const marked = (page: Page) => page.evaluate(() => (window as unknown as { mark?: boolean }).mark === true);

// Coming back to the tab is when the app asks (as well as every five minutes while it is shown).
const showTab = (page: Page) => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));

test('a new build: the banner, and the next page loads it in full', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/audit');
	const banner = page.getByRole('alert', { name: 'New version' });

	// The same build: nothing to say, and moving between pages stays in the app.
	await showTab(page);
	await mark(page);
	await page.getByRole('link', { name: 'pihole-rbac', exact: true }).click();
	await expect(page).toHaveURL(/\/dashboard/);
	expect(await marked(page)).toBe(true);
	await expect(banner).toHaveCount(0);

	await page.route('**/_app/version.json', (route) => route.fulfill({ json: { version: 'the-new-build' } }));
	await showTab(page);
	await expect(banner).toContainText('pihole-rbac has been updated since this page was loaded.');

	await page.goBack(); // a client-side move, like any link
	await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible();
	await expect.poll(() => marked(page)).toBe(false);
});

test('the banner reloads the page', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/audit');
	await page.route('**/_app/version.json', (route) => route.fulfill({ json: { version: 'the-new-build' } }));
	await showTab(page);
	await mark(page);
	await page.getByRole('alert', { name: 'New version' }).getByRole('button', { name: 'Reload' }).click();
	await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible();
	await expect.poll(() => marked(page)).toBe(false);
});
