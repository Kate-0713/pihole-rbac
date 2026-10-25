// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The audit page and the retention setting, against the seeded server. bob holds audit.view and nothing else. Each test
// makes the entries it looks for under names of its own, so it doesn't depend on what other tests wrote.
import type { Page } from '@playwright/test';
import { apiWrite, expect, logIn, openAs, test } from './fixtures.js';

const rows = (page: Page) => page.locator('tbody tr[data-entry]');

// failLogin makes a failed login under a name nobody has, from a browser of its own.
async function failLogin(page: Page, username: string) {
	await page.goto('/login');
	await logIn(page, { username, password: 'not-the-password', about: '' });
	await expect(page.getByRole('alert')).toBeVisible();
}

test('read and filter the audit log, then export it', async ({ page, browser, state }) => {
	const stranger = `nobody-${Date.now()}`;
	const other = await browser.newContext({ baseURL: state.seeded.url });
	await failLogin(await other.newPage(), stranger);
	await other.close();

	await openAs(page, state.seeded.fixture.no_instances, '/');
	await page.getByRole('button', { name: 'Admin' }).click();
	await page.getByRole('menuitem', { name: 'Audit log' }).click();
	await expect(page).toHaveURL('/admin/audit');
	await expect(page).toHaveTitle('Audit log · pihole-rbac');
	await expect(rows(page).first()).toBeVisible();

	// Filter by the stranger's name: one failed login, with the error under the badge.
	await page.getByLabel('User').fill(stranger);
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(`/admin/audit?user=${stranger}`);
	await expect(rows(page)).toHaveCount(1);
	const row = rows(page).first();
	await expect(row.getByText('Failed')).toBeVisible();
	await expect(row.getByText('invalid username or password')).toBeVisible();

	// Its details open in place, as text.
	await row.getByRole('button', { name: `Show the details of login by ${stranger}` }).click();
	const detail = page.locator('tbody tr[id^="audit-detail-"]');
	await expect(detail.getByText('"error": "invalid username or password"')).toBeVisible();
	await expect(detail.getByText('127.0.0.1')).toBeVisible();

	// The export link carries the same filters, and gives a CSV with the row in it.
	const href = await page.getByRole('link', { name: 'Export CSV' }).getAttribute('href');
	expect(href).toBe(`/api/v1/audit/export?user=${stranger}`);
	const csv = await page.request.get(href!);
	expect(csv.headers()['content-type']).toBe('text/csv');
	expect(csv.headers()['content-disposition']).toMatch(/^attachment; filename="pihole-rbac-audit-\d{8}-\d{6}\.csv"$/);
	const lines = (await csv.text()).trim().split('\n');
	expect(lines[0]).toBe('id,time,user,action,target,instance_id,instance,result,ip,detail');
	expect(lines).toHaveLength(2);
	expect(lines[1]).toContain(`,${stranger},login,`);

	// Clicking an action filters by it, keeping the user; failures only, then a time range that holds nothing.
	await row.getByRole('link', { name: 'login', exact: true }).click();
	await expect(page).toHaveURL(`/admin/audit?user=${stranger}&action=login`);
	await expect(page.getByLabel('Actions')).toHaveValue('login');
	await expect(rows(page)).toHaveCount(1);
	await page.getByLabel('From').fill('2099-01-01T00:00');
	await page.getByRole('button', { name: 'Apply' }).click();
	await expect(page).toHaveURL(/&from=2099-01-01T/);
	await expect(page.getByText('No entries match these filters.')).toBeVisible();

	// A bad action name is caught before sending; Clear filters goes back to everything.
	await page.getByLabel('Actions').fill('Login');
	await expect(page.getByText('"Login" isn\'t an action name')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Apply' })).toBeDisabled();
	await page.getByRole('link', { name: 'Clear filters' }).click();
	await expect(page).toHaveURL('/admin/audit');
	await expect(page.getByLabel('User')).toHaveValue('');
	await expect(rows(page).first()).toBeVisible();
});

test('filter by an instance, which keeps its name once deleted', async ({ page, browser, state }) => {
	const name = `audit-probe-${Date.now()}`;
	const admin = await browser.newContext({ baseURL: state.seeded.url });
	const adminPage = await admin.newPage();
	await openAs(adminPage, state.seeded.fixture.admin, '/admin/instances');
	const { id } = await (await apiWrite(adminPage, 'POST', '/api/v1/instances', { name, base_url: 'http://127.0.0.1:9' })).json();

	await openAs(page, state.seeded.fixture.no_instances, `/admin/audit?action=instance_create&action=instance_delete`);
	const created = rows(page).filter({ hasText: name });
	await expect(created).toHaveCount(1);
	await created.getByRole('link', { name, exact: true }).click();
	await expect(page).toHaveURL(`/admin/audit?action=instance_create&action=instance_delete&instance_id=${id}`);
	await expect(page.getByText('Only entries about')).toBeVisible();
	await expect(rows(page)).toHaveCount(1);

	// Deleted: its rows no longer point at an instance, so the filter finds none, and the name stays as plain text.
	await apiWrite(adminPage, 'DELETE', `/api/v1/instances/${id}`);
	await admin.close();
	await page.getByRole('button', { name: 'Refresh' }).click();
	await expect(page.getByText('No entries match these filters.')).toBeVisible();
	await page.getByRole('link', { name: `Stop filtering by instance` }).click();
	await expect(page).toHaveURL('/admin/audit?action=instance_create&action=instance_delete');
	const both = rows(page).filter({ hasText: name });
	await expect(both).toHaveCount(2);
	await expect(both.getByRole('link', { name, exact: true })).toHaveCount(0);
	await expect(both.getByTitle('Deleted')).toHaveCount(2);
});

test('the audit log needs audit.view', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/admin/audit');
	await expect(page.getByText('You need the audit.view permission')).toBeVisible();
	await expect(page.getByRole('link', { name: 'Export CSV' })).toHaveCount(0);
});

test('the audit retention setting', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/settings');
	const days = page.getByLabel('Keep entries for (days)');
	await expect(days).toHaveValue('365');
	await expect(page.getByText('Entries older than 1 year are deleted once a day.')).toBeVisible();
	const card = page.locator('[data-slot="card"]').filter({ has: days });
	const save = card.getByRole('button', { name: 'Save' });

	await days.fill('20');
	await expect(page.getByText('Use 30 to 3650 days (10 years).')).toBeVisible();
	await expect(save).toBeDisabled();

	// A shorter retention warns that older entries go for good.
	await days.fill('90');
	await expect(page.getByText(/Entries older than 90 days are deleted a few seconds after saving/)).toBeVisible();
	await save.click();
	await expect(page.getByText('Audit retention saved.')).toBeVisible();
	await page.reload();
	await expect(days).toHaveValue('90');
	// The session settings were sent unchanged.
	await expect(page.getByLabel('Session lifetime (minutes)')).toHaveValue('480');

	// Put the default back for the other tests.
	await days.fill('365');
	await save.click();
	await expect(page.getByText('Audit retention saved.')).toBeVisible();
});
