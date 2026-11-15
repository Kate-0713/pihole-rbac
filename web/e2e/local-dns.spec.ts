// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The Local DNS page, against the seeded server. pihole1's fake Pi-hole starts with two records (nas.lab, and
// printer.lab with a second name and a comment, as if added in Pi-hole's own admin) and one CNAME, files.lab, with
// app_sudo on (see the e2e server). Tests that add an entry delete it again.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const entry = (page: Page, key: string) => page.locator(`tr[data-entry="${key}"]`);
const records = (page: Page) => page.getByRole('region', { name: 'Records' });
const cnames = (page: Page) => page.getByRole('region', { name: 'CNAMEs' });

// Deletes an entry through the API if a test left it behind.
async function removeEntry(page: Page, kind: 'records' | 'cnames', key: string, value: string) {
	const res = await page.request.get('/api/v1/targets/i-1/local-dns');
	const dns = (await res.json()) as { records: { key: string }[]; cnames: { key: string }[] };
	if (!dns[kind].some((e) => e.key === key)) return;
	const body = kind === 'records' ? { record: { value }, reason: 'e2e clean-up' } : { cname: { value }, reason: 'e2e clean-up' };
	await apiWrite(page, 'DELETE', `/api/v1/targets/i-1/local-dns/${kind}`, body);
}

async function setLocalDNSSettings(page: Page, settings: { localdns_reason_required?: boolean; localdns_extra_domains?: string[] }) {
	const res = await page.request.get('/api/v1/settings/general');
	const g = (await res.json()) as { session_lifetime_minutes: number; idle_timeout_minutes: number };
	await apiWrite(page, 'PUT', '/api/v1/settings/general', {
		session_lifetime_minutes: g.session_lifetime_minutes,
		idle_timeout_minutes: g.idle_timeout_minutes,
		...settings
	});
}

test('lists the records and CNAMEs', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Local DNS' }).click();
	await expect(page).toHaveURL('/local-dns?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Local DNS · pihole-rbac');

	await expect(entry(page, '10.0.0.5 nas.lab')).toContainText('10.0.0.5');
	await expect(entry(page, '10.0.0.5 nas.lab')).toContainText('No reason recorded');
	const printer = entry(page, '10.0.0.6 printer.lab printer');
	await expect(printer).toContainText('also printer');
	await expect(printer).toContainText('Several names');
	await expect(printer).toContainText('Comment');
	await expect(printer.getByRole('button', { name: 'Replace printer.lab' })).toBeVisible();
	await expect(entry(page, 'files.lab,nas.lab')).toContainText('Default');

	// The search narrows one table.
	await records(page).getByLabel('Search records').fill('printer');
	await expect(records(page).getByText('Showing 1 of 2 records')).toBeVisible();
	await expect(entry(page, '10.0.0.5 nas.lab')).toHaveCount(0);
	await expect(entry(page, 'files.lab,nas.lab')).toBeVisible();
});

test("a user without localdns.view doesn't see the page", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await expect(page.getByRole('link', { name: 'Local DNS' })).toHaveCount(0);
	await page.goto('/local-dns?target=i-1');
	await expect(page.getByText("You can't view the local DNS of pihole1.")).toBeVisible();
});

test('adding, changing and deleting a record, with reasons', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/local-dns?target=i-1');
	try {
		await page.getByRole('button', { name: 'Add a record' }).click();
		const dialog = page.getByRole('dialog');
		// The rules are checked as you type.
		await dialog.getByLabel('Hostname').fill('tv lab');
		await dialog.getByLabel('Address').fill('10.0.0.256');
		await expect(dialog.getByText('Use letters, digits, hyphens and dots only.')).toBeVisible();
		await expect(dialog.getByText("That isn't a valid IPv4 or IPv6 address.")).toBeVisible();
		await expect(dialog.getByText('Give a reason for the change.')).toBeVisible();
		await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
		await dialog.getByLabel('Hostname').fill('TV.lab');
		await dialog.getByLabel('Address').fill('10.0.0.7');
		await dialog.getByLabel('Reason').fill('the new TV');
		await dialog.getByRole('button', { name: 'Add' }).click();
		await expect(page.getByText('TV.lab (10.0.0.7) added on pihole1.')).toBeVisible();
		const tv = entry(page, '10.0.0.7 tv.lab');
		await expect(tv).toContainText('the new TV');
		await expect(tv).toContainText('by admin');

		await page.getByRole('button', { name: 'Change tv.lab' }).click();
		await expect(dialog.getByLabel('Hostname')).toHaveValue('tv.lab');
		await dialog.getByLabel('Address').fill('10.0.0.17');
		await dialog.getByLabel('Reason').fill('moved to another port');
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('tv.lab (10.0.0.17) saved on pihole1.')).toBeVisible();
		await expect(tv).toHaveCount(0);
		const moved = entry(page, '10.0.0.17 tv.lab');
		await expect(moved).toContainText('moved to another port');

		await page.getByRole('button', { name: 'Delete tv.lab' }).click();
		const confirm = page.getByRole('alertdialog');
		await confirm.getByRole('button', { name: 'Delete' }).click();
		// No reason yet: the dialog stays open and says so.
		await expect(confirm.getByText('Give a reason for the change.')).toBeVisible();
		await confirm.getByLabel('Reason').fill('gone');
		await confirm.getByRole('button', { name: 'Delete' }).click();
		await expect(page.getByText('tv.lab (10.0.0.17) deleted on pihole1.')).toBeVisible();
		await expect(moved).toHaveCount(0);
	} finally {
		await removeEntry(page, 'records', '10.0.0.7 tv.lab', '10.0.0.7 tv.lab');
		await removeEntry(page, 'records', '10.0.0.17 tv.lab', '10.0.0.17 tv.lab');
	}
});

test('a CNAME, and a name under a directory domain', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/settings');
	try {
		// The settings: a directory domain, and reasons made optional.
		const card = page.getByRole('region', { name: 'Local DNS' });
		await card.getByLabel('Extra directory domains').fill('corp.example, bad_domain');
		await expect(card.getByText(/bad_domain: Use letters/)).toBeVisible();
		await card.getByLabel('Extra directory domains').fill('Corp.example');
		await card.getByLabel('Require a reason for every change').uncheck();
		await card.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('Local DNS settings saved.')).toBeVisible();

		await page.goto('/local-dns?target=i-1');
		await page.getByRole('button', { name: 'Add a CNAME' }).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog.getByText('Saving restarts DNS on pihole1')).toBeVisible();
		await expect(dialog.getByLabel('Reason (optional)')).toBeVisible();
		await dialog.getByLabel('Alias').fill('wiki.corp.example');
		// A target Pi-hole doesn't know itself gets a warning: the CNAME would be answered without an address.
		await dialog.getByLabel('Target').fill('example.com');
		await expect(dialog.getByText("example.com isn't one of pihole1's own records.", { exact: false })).toBeVisible();
		await dialog.getByLabel('Target').fill('nas.lab');
		await expect(dialog.getByText("isn't one of pihole1's own records", { exact: false })).toHaveCount(0);
		await dialog.getByLabel('TTL (seconds)').fill('300');
		await dialog.getByRole('button', { name: 'Add' }).click();
		// The server asks first: a local name in the directory's domain can hide a real one.
		await expect(dialog.getByText(/is in the directory's domain corp\.example/)).toBeVisible();
		await dialog.getByRole('button', { name: 'Save anyway' }).click();
		await expect(page.getByText('wiki.corp.example → nas.lab, TTL 300s added on pihole1.')).toBeVisible();
		const wiki = entry(page, 'wiki.corp.example,nas.lab,300');
		await expect(wiki).toContainText('300s');
		await expect(wiki).toContainText('No reason given');

		await page.getByRole('button', { name: 'Delete wiki.corp.example' }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm).toContainText('Deleting it restarts DNS on the Pi-hole.');
		await confirm.getByRole('button', { name: 'Delete' }).click();
		await expect(page.getByText(/wiki\.corp\.example → nas\.lab, TTL 300s deleted on pihole1\./)).toBeVisible();
		await expect(wiki).toHaveCount(0);
	} finally {
		await removeEntry(page, 'cnames', 'wiki.corp.example,nas.lab,300', 'wiki.corp.example,nas.lab,300');
		await setLocalDNSSettings(page, { localdns_reason_required: true, localdns_extra_domains: [] });
	}
});

test('an entry added outside the app is replaced by one the app writes', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/local-dns?target=i-1');
	const original = '10.0.0.6 printer.lab printer # office';
	try {
		await page.getByRole('button', { name: 'Replace printer.lab' }).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog).toContainText(original);
		await expect(dialog.getByLabel('Hostname')).toHaveValue('printer.lab');
		await expect(dialog.getByLabel('Address')).toHaveValue('10.0.0.6');
		await dialog.getByLabel('Reason').fill('one name');
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('printer.lab (10.0.0.6) saved on pihole1.')).toBeVisible();
		await expect(entry(page, '10.0.0.6 printer.lab printer')).toHaveCount(0);
		await expect(entry(page, '10.0.0.6 printer.lab')).toContainText('one name');
	} finally {
		// The seeded entry can't be put back through the app, which won't write two names or a comment, so this test
		// comes last in the file. drift.spec.ts, which needs it, runs before this file.
		await removeEntry(page, 'records', '10.0.0.6 printer.lab', '10.0.0.6 printer.lab');
	}
});
