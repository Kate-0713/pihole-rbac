// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Light and dark mode: the header's switch, the choice kept in this browser, following the operating system, and the
// inline script in app.html that applies the choice before the app loads (which the CSP must allow by its hash; the
// fixtures fail any test that logs a CSP violation).
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

const html = (page: Page) => page.locator('html');

async function choose(page: Page, current: string, next: string) {
	await page.getByRole('button', { name: `Theme: ${current}` }).click();
	await page.getByRole('menuitemradio', { name: next }).click();
	await expect(page.getByRole('menu')).toHaveCount(0); // a pick closes the menu
	await expect(page.getByRole('button', { name: `Theme: ${next}` })).toBeVisible();
}

test('the theme switch: dark, kept after a reload, then back to following the system', async ({ page, state }) => {
	await page.emulateMedia({ colorScheme: 'light' });
	await openAs(page, state.seeded.fixture.admin, '/admin/audit');
	await expect(html(page)).not.toHaveClass(/\bdark\b/);

	await choose(page, 'System', 'Dark');
	await expect(html(page)).toHaveClass(/\bdark\b/);
	await expect(html(page)).toHaveCSS('color-scheme', 'dark');

	await page.reload();
	await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible();
	await expect(html(page)).toHaveClass(/\bdark\b/);

	// Light wins over a dark operating system; System follows it, as it changes.
	await page.emulateMedia({ colorScheme: 'dark' });
	await choose(page, 'Dark', 'Light');
	await expect(html(page)).not.toHaveClass(/\bdark\b/);
	await choose(page, 'Light', 'System');
	await expect(html(page)).toHaveClass(/\bdark\b/);
	await page.emulateMedia({ colorScheme: 'light' });
	await expect(html(page)).not.toHaveClass(/\bdark\b/);
});

test('the choice is applied before the app loads, so a dark page never flashes white', async ({ page, state, problems }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/audit');
	await choose(page, 'System', 'Dark');

	// With the app's own scripts blocked, only app.html's inline script can have set the class.
	await page.route('**/_app/**', (route) => route.abort());
	await page.goto('/login');
	await expect(html(page)).toHaveClass(/\bdark\b/);
	// Blocking the bundles is this test's doing, so the error it causes is expected; anything else (a CSP violation
	// from the inline script, say) still fails the test.
	const expected = (p: string) => p.includes('Failed to fetch dynamically imported module');
	expect(problems.filter((p) => !expected(p))).toEqual([]);
	problems.splice(0, problems.length);
});
