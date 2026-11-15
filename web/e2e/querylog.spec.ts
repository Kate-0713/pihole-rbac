// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The query log page, against the seeded server. pihole1's fake Pi-hole has five queries, newest first (see the e2e
// server): ads.example (GRAVITY, printer.lan), school.example (FORWARDED, 10.0.0.7), games.example (DENYLIST,
// printer.lan), school.example (CACHE, AAAA, 10.0.0.8) and news.example (FORWARDED, 10.0.0.7). pihole2's has 60
// cached queries, page-60.example to page-01.example, ending ten minutes ago, and on disk one more from two days ago,
// archive.example. Every filter and page is read by the server. The page only reads, so the tests can run in any
// order.
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

const domains = (page: Page) => page.locator('tbody tr td:nth-child(3)');
const all = ['ads.example', 'school.example', 'games.example', 'school.example', 'news.example'];

async function choose(page: Page, label: string, option: string) {
	await page.getByRole('combobox', { name: label }).click();
	await page.getByRole('option', { name: option, exact: true }).click();
}

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

	// No sorting in the browser, and no pager for a single page.
	await expect(page.getByRole('columnheader', { name: 'Time' }).getByRole('button')).toHaveCount(0);
	await expect(page.getByRole('navigation', { name: 'Pages' })).toHaveCount(0);
	await page.getByRole('button', { name: 'Refresh' }).click();
	await expect(domains(page)).toHaveText(all);
});

test('the domain filter goes in the URL, and Back undoes it', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await page.getByLabel('Domain contains').fill('SCHOOL');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(/\/querylog\?target=i-1&domain=SCHOOL$/);
	await expect(domains(page)).toHaveText(['school.example', 'school.example']);
	await expect(page.getByText('2 queries', { exact: true })).toBeVisible();

	await page.goBack();
	await expect(domains(page)).toHaveText(all);
	await expect(page.getByLabel('Domain contains')).toHaveValue('');

	await page.getByLabel('Domain contains').fill('nothing-like-this');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page.getByText('No queries match.')).toBeVisible();
	await page.getByRole('link', { name: 'Clear filters' }).click();
	await expect(domains(page)).toHaveText(all);
});

test('a filter the server would refuse is explained, and not sent', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await page.getByLabel('Client contains').fill('my pc');
	await expect(page.getByText('Letters, digits, dots, colons, hyphens, underscores and * only.')).toBeVisible();
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL('/querylog?target=i-1');
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

test('result, status and type are filtered by the server', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await choose(page, 'Result', 'Blocked');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(/result=blocked/);
	await expect(domains(page)).toHaveText(['ads.example', 'games.example']);

	await choose(page, 'Result', 'Allowed');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(domains(page)).toHaveText(['school.example', 'school.example', 'news.example']);

	await choose(page, 'Result', 'All results');
	await choose(page, 'Status', 'Cached');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(/status=CACHE/);
	await expect(domains(page)).toHaveText(['school.example']);

	await page.goto('/querylog?target=i-1&type=AAAA');
	await expect(domains(page)).toHaveText(['school.example']);
	await expect(page.getByRole('combobox', { name: 'Type' })).toHaveText('AAAA');
});

test('numbered pages, kept in the URL, stable while the snapshot holds', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-2&page_size=25');
	await expect(page.getByText('60 queries, page 1 of 3')).toBeVisible();
	await expect(domains(page).first()).toHaveText('page-60.example');
	const pager = page.getByRole('navigation', { name: 'Pages' });
	await expect(pager.getByRole('link', { name: 'Page 1' })).toHaveAttribute('aria-current', 'page');

	// Hovering a page doesn't read it: each read can be large, so the page preloads on a press, not on hover.
	let reads = 0;
	const count = (r: { url(): string }) => void (r.url().includes('/queries?') && reads++);
	page.on('request', count);
	await pager.getByRole('link', { name: 'Page 3' }).hover();
	await page.waitForTimeout(500);
	page.off('request', count);
	expect(reads).toBe(0);

	// Later pages send the first page's snapshot; the URL never holds it.
	const second = page.waitForRequest((r) => r.url().includes('/queries?') && r.url().includes('page=2'));
	await pager.getByRole('link', { name: 'Next page' }).click();
	expect(new URL((await second).url()).searchParams.get('snapshot')).toMatch(/^v1\./);
	await expect(page).toHaveURL('/querylog?target=i-2&page_size=25&page=2');
	await expect(domains(page).first()).toHaveText('page-35.example');

	await pager.getByRole('link', { name: 'Last page' }).click();
	await expect(page.getByText('60 queries, page 3 of 3')).toBeVisible();
	await expect(domains(page)).toHaveCount(10);
	await page.goBack();
	await expect(domains(page).first()).toHaveText('page-35.example');

	await page.getByLabel('Go to page').fill('9');
	await expect(page.getByText('Pick a page from 1 to 3.')).toBeVisible();
	await page.getByLabel('Go to page').fill('1');
	await page.getByRole('button', { name: 'Go', exact: true }).click();
	await expect(page).toHaveURL('/querylog?target=i-2&page_size=25');

	// A new page size is a new search, from page 1.
	await choose(page, 'Per page', '50 per page');
	await expect(page).toHaveURL('/querylog?target=i-2&page_size=50');
	await expect(page.getByText('60 queries, page 1 of 2')).toBeVisible();

	// A page past the last says so.
	await page.goto('/querylog?target=i-2&page=9');
	await expect(page.getByText('There are no queries on this page.')).toBeVisible();
});

test('an older time range is read from the long-term database', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-2');
	await expect(page.getByText('60 queries', { exact: true })).toBeVisible();
	await choose(page, 'When', 'Last 7 days');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL('/querylog?target=i-2&range=7d');
	await expect(page.getByText('61 queries · from the long-term database')).toBeVisible();
	await expect(domains(page).last()).toHaveText('archive.example');

	await choose(page, 'When', 'Last hour');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page.getByText(/^\d+ queries$/)).toBeVisible();
	await expect(page.getByRole('cell', { name: 'archive.example' })).toHaveCount(0);
});

test('columns can be hidden, and stay hidden in this browser', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/querylog?target=i-1');
	await expect(page.getByRole('columnheader', { name: 'Upstream' })).toBeVisible();
	await page.getByRole('button', { name: 'Columns' }).click();
	await page.getByRole('menuitemcheckbox', { name: 'Upstream' }).click();
	await page.keyboard.press('Escape');
	await expect(page.getByRole('columnheader', { name: 'Upstream' })).toHaveCount(0);
	await page.reload();
	await expect(page.getByRole('columnheader', { name: 'Domain' })).toBeVisible();
	await expect(page.getByRole('columnheader', { name: 'Upstream' })).toHaveCount(0);

	await page.getByRole('button', { name: 'Columns' }).click();
	await page.getByRole('menuitemcheckbox', { name: 'Upstream' }).click();
	await page.keyboard.press('Escape');
	await expect(page.getByRole('columnheader', { name: 'Upstream' })).toBeVisible();
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
