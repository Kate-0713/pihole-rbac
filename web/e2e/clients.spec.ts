// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The clients page, against the seeded server. pihole1's fake Pi-hole starts with two clients (see the e2e server):
// 10.0.0.0/24 ("lab subnet", Default) and 10.0.1.5 (printer.lan, kids). A test that changes one puts it back.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const row = (page: Page, client: string) => page.getByRole('row').filter({ hasText: client });
const clientCells = (page: Page) => page.locator('tbody tr td:first-child');

test('lists the clients with their names and groups', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Clients · pihole-rbac');
	await expect(clientCells(page)).toHaveText(['10.0.0.0/24', '10.0.1.5']);

	const lab = row(page, '10.0.0.0/24');
	await expect(lab).toContainText('Default');
	await expect(lab).toContainText('lab subnet');
	const printer = row(page, '10.0.1.5');
	await expect(printer).toContainText('printer.lan');
	await expect(printer).toContainText('kids');
});

test('search and the group filter narrow the list', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await page.getByLabel('Search').fill('printer'); // matches the name
	await expect(clientCells(page)).toHaveText(['10.0.1.5']);
	await expect(page.getByText('Showing 1 of 2 clients')).toBeVisible();

	await page.getByLabel('Search').fill('');
	await page.getByRole('combobox', { name: 'Group' }).click();
	await page.getByRole('option', { name: 'Default', exact: true }).click();
	await expect(clientCells(page)).toHaveText(['10.0.0.0/24']);

	await page.getByLabel('Search').fill('printer');
	await expect(page.getByText('Nothing matches.')).toBeVisible();
});

test("changing a client's groups and comment", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await page.getByRole('button', { name: 'Change 10.0.0.0/24' }).click();
	const dialog = page.getByRole('dialog');
	await expect(dialog).toContainText('10.0.0.0/24 on pihole1.');
	await expect(dialog.getByLabel('Comment')).toHaveValue('lab subnet');
	await expect(dialog.getByLabel('Default')).toBeChecked();
	await dialog.getByLabel('kids').click();
	await dialog.getByLabel('Comment').fill('lab and kids');
	await dialog.getByRole('button', { name: 'Save' }).click();

	await expect(page.getByText('10.0.0.0/24 updated on pihole1.')).toBeVisible();
	await expect(dialog).toHaveCount(0);
	const lab = row(page, '10.0.0.0/24');
	await expect(lab).toContainText('Default, kids');
	await expect(lab).toContainText('lab and kids');

	await apiWrite(page, 'PATCH', '/api/v1/targets/i-1/clients', {
		client: '10.0.0.0/24',
		comment: 'lab subnet',
		groups: [0]
	});
});

test('a comment with a line break is caught before sending', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await page.getByRole('button', { name: 'Change 10.0.1.5' }).click();
	const dialog = page.getByRole('dialog');
	await expect(dialog).toContainText('10.0.1.5 (printer.lan) on pihole1.');
	await dialog.getByLabel('Comment').fill('two\tparts');
	await expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled();
	await dialog.getByRole('button', { name: 'Cancel' }).click();
	await expect(row(page, '10.0.1.5')).toContainText('kids');
});

test('without clients.edit the list is read-only', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/clients?target=i-1');
	await expect(clientCells(page)).toHaveCount(2);
	await expect(page.getByRole('button', { name: /^Change / })).toHaveCount(0);
});

test('an instance that is down says so, with a way to try again', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-3');
	await expect(page.getByRole('alert')).toContainText(`Couldn't read the clients: Pi-hole "pihole3"`);
	await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
});
