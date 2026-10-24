// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The query log page, against the seeded server. pihole1's fake Pi-hole has five queries, newest first (see the e2e
// server): ads.example (GRAVITY, printer.lan), school.example (FORWARDED, 10.0.0.7), games.example (DENYLIST,
// printer.lan), school.example (CACHE, 10.0.0.8) and news.example (FORWARDED, 10.0.0.7). The page only reads, so the
// tests can run in any order.
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

const domains = (page: Page) => page.locator('tbody tr td:nth-child(3)');
const all = ['ads.example', 'school.example', 'games.example', 'school.example', 'news.example'];

test('lists the newest queries first, with their status', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Query log · pihole-rbac');
	await expect(domains(page)).toHaveText(all);
	await expect(page.getByText('5 queries', { exact: true })).toBeVisible();

	const ads = page.locator('tbody tr').first();
	await expect(ads).toContainText('Blocked (gravity)');
	await expect(ads).toContainText('printer.lan');
	await expect(ads).toContainText('10.0.1.5');
	await expect(ads).toContainText('0.10 ms');
	await expect(page.locator('tbody tr').nth(1)).toContainText('9.9.9.9#53');

	// Oldest first, and Refresh reads the log again without losing the order.
	const header = page.getByRole('columnheader', { name: 'Time' });
	await expect(header).toHaveAttribute('aria-sort', 'descending');
	await header.getByRole('button').click();
	await expect(domains(page)).toHaveText([...all].reverse());
	await page.getByRole('button', { name: 'Refresh' }).click();
	await expect(domains(page)).toHaveText([...all].reverse());
});

test('the domain filter goes in the URL, and Back undoes it', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await page.getByLabel('Domain contains').fill('SCHOOL');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(/\/querylog\?target=i-1&domain=SCHOOL$/);
	await expect(domains(page)).toHaveText(['school.example', 'school.example']);
	await expect(page.getByText('The filters are applied to the newest 100 queries')).toBeVisible();

	await page.goBack();
	await expect(domains(page)).toHaveText(all);
	await expect(page.getByLabel('Domain contains')).toHaveValue('');

	await page.getByLabel('Domain contains').fill('nothing-like-this');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page.getByText('No queries match among the newest 100.')).toBeVisible();
	await page.getByRole('link', { name: 'Clear filters' }).click();
	await expect(domains(page)).toHaveText(all);
});

test('clicking a client narrows the log to it', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await page.getByRole('link', { name: /printer\.lan/ }).first().click();
	await expect(page).toHaveURL(/client=10\.0\.1\.5/);
	await expect(domains(page)).toHaveText(['ads.example', 'games.example']);
	await expect(page.getByLabel('Client contains')).toHaveValue('10.0.1.5');

	// The client filter matches names too.
	await page.getByLabel('Client contains').fill('PRINTER');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(domains(page)).toHaveText(['ads.example', 'games.example']);
});

test('blocked or allowed only, among what was read', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await page.getByRole('combobox', { name: 'Result' }).click();
	await page.getByRole('option', { name: 'Blocked', exact: true }).click();
	await expect(domains(page)).toHaveText(['ads.example', 'games.example']);
	await expect(page.getByText('Showing 2 of 5 queries')).toBeVisible();

	await page.getByRole('combobox', { name: 'Result' }).click();
	await page.getByRole('option', { name: 'Allowed', exact: true }).click();
	await expect(domains(page)).toHaveText(['school.example', 'school.example', 'news.example']);
});

test('how many entries to read', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1&length=2');
	await expect(domains(page)).toHaveText(['ads.example', 'school.example']);
	await expect(page.getByRole('combobox', { name: 'Read the newest' })).toHaveText('2 queries');

	await page.getByRole('combobox', { name: 'Read the newest' }).click();
	await page.getByRole('option', { name: '250 queries' }).click();
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(/length=250/);
	await expect(domains(page)).toHaveText(all);

	// A length the server would refuse falls back to the default.
	await page.goto('/querylog?target=i-1&length=5000');
	await expect(domains(page)).toHaveText(all);
	await expect(page.getByRole('combobox', { name: 'Read the newest' })).toHaveText('100 queries');
});

test('a user with querylog.view on the instance can read it', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/querylog?target=i-1');
	await expect(domains(page)).toHaveCount(5);
});

test('an instance that is down says so, with a way to try again', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-3');
	await expect(page.getByRole('alert')).toContainText(`Couldn't read the query log: Pi-hole "pihole3"`);
	await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
});
