// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The domains page, against the seeded server. pihole1's fake Pi-hole starts with three entries (see the e2e
// server): ads.example (deny, Default, "tracker"), games.example (deny, kids) and school.example (allow, Default and
// kids). Tests that change an entry put it back, and tests that add one delete it, so they don't depend on order.
import type { Locator, Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const row = (page: Page, domain: string) => page.getByRole('row').filter({ hasText: domain });
const domainCells = (page: Page) => page.locator('tbody tr td:first-child');

// chooseOption picks from a Select inside `within` (the page's filters, or a dialog, which has its own List and
// Match). The options open in a layer of their own, outside `within`, so they are found on the page.
async function chooseOption(page: Page, within: Page | Locator, trigger: string, option: string) {
	await within.getByRole('combobox', { name: trigger }).click();
	await page.getByRole('option', { name: option, exact: true }).click();
}

test('lists both lists with their groups, sorted by domain', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Domains · pihole-rbac');
	await expect(domainCells(page)).toHaveText([/^ads\.example/, /^games\.example/, /^school\.example/]);

	const ads = row(page, 'ads.example');
	await expect(ads).toContainText('Deny');
	await expect(ads).toContainText('Default');
	await expect(ads).toContainText('tracker');
	await expect(row(page, 'school.example')).toContainText('Allow');
	await expect(row(page, 'school.example')).toContainText('Default, kids');

	// Sorting the other way, and the header says so.
	const header = page.getByRole('columnheader', { name: 'Domain' });
	await expect(header).toHaveAttribute('aria-sort', 'ascending');
	await header.getByRole('button').click();
	await expect(header).toHaveAttribute('aria-sort', 'descending');
	await expect(domainCells(page)).toHaveText([/^school\.example/, /^games\.example/, /^ads\.example/]);
});

test('search and filters narrow the list', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-1');
	await page.getByLabel('Search').fill('tracker'); // matches the comment
	await expect(domainCells(page)).toHaveText([/^ads\.example/]);
	await expect(page.getByText('Showing 1 of 3 entries')).toBeVisible();

	await page.getByLabel('Search').fill('');
	await chooseOption(page, page, 'List', 'Allow list');
	await expect(domainCells(page)).toHaveText([/^school\.example/]);

	await chooseOption(page, page, 'Match', 'Regex');
	await expect(page.getByText('Nothing matches.')).toBeVisible();
});

test('adding a domain, then deleting it', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-1');
	await page.getByRole('button', { name: 'Add a domain' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Domain', { exact: true }).fill('  new.example  ');
	await dialog.getByLabel('Comment').fill('added by e2e');
	// The Default group is ticked for a new entry; add kids too.
	await expect(dialog.getByLabel('Default')).toBeChecked();
	await dialog.getByLabel('kids').click();
	await dialog.getByRole('button', { name: 'Add' }).click();

	await expect(page.getByText('new.example added to the deny list on pihole1.')).toBeVisible();
	await expect(dialog).toHaveCount(0);
	const added = row(page, 'new.example');
	await expect(added).toContainText('Default, kids');
	await expect(added).toContainText('added by e2e');

	// Delete asks first; Cancel keeps it.
	await page.getByRole('button', { name: 'Delete new.example' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('new.example comes off the deny list (exact) of pihole1.');
	await confirm.getByRole('button', { name: 'Cancel' }).click();
	await expect(added).toBeVisible();

	await page.getByRole('button', { name: 'Delete new.example' }).click();
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText('new.example deleted on pihole1.')).toBeVisible();
	await expect(row(page, 'new.example')).toHaveCount(0);
});

test('a regex goes on the allow list when chosen', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-1');
	await page.getByRole('button', { name: 'Add a domain' }).click();
	const dialog = page.getByRole('dialog');
	await chooseOption(page, dialog, 'Match', 'Regular expression');
	await chooseOption(page, dialog, 'List', 'Allow');
	await dialog.getByLabel('Regular expression').fill('(^|\\.)cdn\\.example$');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText('(^|\\.)cdn\\.example$ added to the allow list on pihole1.')).toBeVisible();

	const added = row(page, 'cdn');
	await expect(added).toContainText('Allow');
	await expect(added).toContainText('Regex');
	await apiWrite(page, 'DELETE', '/api/v1/targets/i-1/domains', { domain: '(^|\\.)cdn\\.example$', type: 'allow', kind: 'regex' });
});

test("Pi-hole's refusal is shown in the dialog, which stays open to fix it", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-1');
	await page.getByRole('button', { name: 'Add a domain' }).click();
	const dialog = page.getByRole('dialog');

	// Caught before sending: the hint shows and Add is disabled.
	await dialog.getByLabel('Domain', { exact: true }).fill('two\tparts');
	await expect(dialog.getByText("It can't contain control characters or line breaks.")).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();

	// Only Pi-hole knows it's a duplicate.
	await dialog.getByLabel('Domain', { exact: true }).fill('ads.example');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog.getByRole('alert')).toContainText('Pi-hole "pihole1" refused the request');
	await expect(dialog).toBeVisible();
	await dialog.getByRole('button', { name: 'Cancel' }).click();
	await expect(row(page, 'ads.example')).toHaveCount(1);
});

test("changing an entry's groups and comment keeps the rest", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-1');
	await page.getByRole('button', { name: 'Change games.example' }).click();
	const dialog = page.getByRole('dialog');
	await expect(dialog).toContainText('games.example on the deny list (exact) of pihole1.');
	await expect(dialog.getByLabel('kids')).toBeChecked();
	await dialog.getByLabel('Default').click();
	await dialog.getByLabel('Comment').fill('consoles');
	await dialog.getByRole('button', { name: 'Save' }).click();

	await expect(page.getByText('games.example updated on pihole1.')).toBeVisible();
	const games = row(page, 'games.example');
	await expect(games).toContainText('Default, kids');
	await expect(games).toContainText('consoles');
	await expect(games).toContainText('Deny');

	await apiWrite(page, 'PATCH', '/api/v1/targets/i-1/domains', {
		domain: 'games.example',
		type: 'deny',
		kind: 'exact',
		comment: '',
		groups: [1]
	});
});

test('without domains.edit the list is read-only', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/domains?target=i-1');
	await expect(domainCells(page)).toHaveCount(3);
	await expect(page.getByRole('button', { name: 'Add a domain' })).toHaveCount(0);
	await expect(page.getByRole('button', { name: /^(Change|Delete) / })).toHaveCount(0);
});

test('an instance that is down says so, with a way to try again', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/domains?target=i-3');
	await expect(page.getByRole('alert')).toContainText(`Couldn't read the domain lists: Pi-hole "pihole3"`);
	await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
	await expect(page.getByRole('button', { name: 'Add a domain' })).toHaveCount(0);
});
