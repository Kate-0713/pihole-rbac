// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The Lists page, against the seeded server. pihole1's fake Pi-hole starts with four lists in Default (see the e2e
// server): ads.txt downloaded, broken.txt whose download failed, a disabled ftp:// allowlist, and new.txt, added
// since the last gravity run. Tests that add a list delete it again. The gravity test runs last in the file, since
// it ends the wait for new.txt.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const row = (page: Page, key: string) => page.locator(`tr[data-list="${key}"]`);
const ads = 'block/https://lists.example/ads.txt';

async function removeList(page: Page, address: string, type: 'block' | 'allow') {
	const res = await page.request.get('/api/v1/targets/i-1/lists');
	const { lists } = (await res.json()) as { lists: { address: string; type: string }[] };
	if (lists.some((l) => l.address === address && l.type === type)) {
		await apiWrite(page, 'DELETE', '/api/v1/targets/i-1/lists', { address, type });
	}
}

test('lists the subscriptions with their status', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/lists?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Lists · pihole-rbac');
	await expect(row(page, ads)).toContainText('Updated');
	await expect(row(page, ads)).toContainText('5,000');
	await expect(row(page, ads)).toContainText('ads');
	await expect(row(page, 'block/https://lists.example/broken.txt')).toContainText('Download failed');
	const old = row(page, 'allow/ftp://lists.example/old.txt');
	await expect(old).toContainText('Other scheme');
	await expect(old).toContainText('Disabled');
	await expect(row(page, 'block/https://lists.example/new.txt')).toContainText('Waiting for gravity');
	await expect(page.getByText('1 list is waiting for a gravity update.')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Run gravity now' })).toBeVisible();

	// Filtering by type.
	await page.getByRole('combobox', { name: 'Type' }).click();
	await page.getByRole('option', { name: 'Allowlists' }).click();
	await expect(page.getByText('Showing 1 of 4 lists')).toBeVisible();
	await expect(row(page, ads)).toHaveCount(0);
});

test("a user without lists.view doesn't see the page", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await expect(page.getByRole('link', { name: 'Lists' })).toHaveCount(0);
	await page.goto('/lists?target=i-1');
	await expect(page.getByText("You can't view the lists of pihole1.")).toBeVisible();
});

test('adding, changing, disabling and deleting a list', async ({ page, state }) => {
	const address = 'https://lists.example/e2e.txt';
	await openAs(page, state.seeded.fixture.admin, '/lists?target=i-1');
	try {
		await page.getByRole('button', { name: 'Add a list' }).click();
		const dialog = page.getByRole('dialog');
		// The address rules are checked as you type: no login in the address, http and https only.
		await dialog.getByLabel('Address').fill('https://user:secret@lists.example/e2e.txt');
		await expect(dialog.getByText(/Leave the user name and password out/)).toBeVisible();
		await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
		await dialog.getByLabel('Address').fill('ftp://lists.example/e2e.txt');
		await expect(dialog.getByText("ftp: addresses aren't allowed, only http and https.")).toBeVisible();
		await dialog.getByLabel('Address').fill(address);
		await dialog.getByLabel('Comment').fill('added by e2e');
		await dialog.getByRole('button', { name: 'Add' }).click();
		await expect(page.getByText(`${address} added on pihole1.`)).toBeVisible();
		await expect(page.getByText('Pi-hole starts using it after the next gravity update.')).toBeVisible();
		const r = row(page, `block/${address}`);
		await expect(r).toContainText('added by e2e');
		await expect(r).toContainText('Waiting for gravity');
		await expect(page.getByText('2 lists are waiting for a gravity update.')).toBeVisible();

		await page.getByRole('button', { name: `Change ${address}` }).click();
		await dialog.getByLabel('Comment').fill('changed by e2e');
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText(`${address} updated on pihole1.`)).toBeVisible();
		await expect(r).toContainText('changed by e2e');

		await page.getByRole('button', { name: `Disable ${address}` }).click();
		await expect(page.getByText(`${address} disabled on pihole1.`)).toBeVisible();
		await expect(r).toContainText('Disabled');
		await expect(r).not.toContainText('Waiting for gravity');
		await page.getByRole('button', { name: `Enable ${address}` }).click();
		await expect(page.getByText(`${address} enabled on pihole1.`)).toBeVisible();

		await page.getByRole('button', { name: `Delete ${address}` }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm).toContainText('Its domains stop applying at once.');
		await confirm.getByRole('button', { name: 'Delete' }).click();
		await expect(page.getByText(`${address} deleted on pihole1.`)).toBeVisible();
		await expect(r).toHaveCount(0);
	} finally {
		await removeList(page, address, 'block');
	}
});

test('file: lists need the setting', async ({ page, state }) => {
	const address = 'file:///etc/pihole/e2e.txt';
	await openAs(page, state.seeded.fixture.admin, '/lists?target=i-1');
	const add = async () => {
		await page.getByRole('button', { name: 'Add a list' }).click();
		const dialog = page.getByRole('dialog');
		await dialog.getByLabel('Address').fill(address);
		await dialog.getByRole('button', { name: 'Add' }).click();
		return dialog;
	};
	try {
		// Off by default: the server refuses, and says where to change it.
		const dialog = await add();
		await expect(dialog.getByText(/file: lists aren't allowed/)).toBeVisible();
		await dialog.getByRole('button', { name: 'Cancel' }).click();

		await page.goto('/admin/settings');
		await page.getByLabel('Allow file: lists').check();
		await page.getByRole('region', { name: 'Lists' }).getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('file: lists can now be added.')).toBeVisible();

		await page.goto('/lists?target=i-1');
		await add();
		await expect(page.getByText(`${address} added on pihole1.`)).toBeVisible();
		await expect(row(page, `block/${address}`)).toContainText('file: list');
	} finally {
		await removeList(page, address, 'block');
		const res = await page.request.get('/api/v1/settings/general');
		const g = (await res.json()) as { session_lifetime_minutes: number; idle_timeout_minutes: number };
		await apiWrite(page, 'PUT', '/api/v1/settings/general', {
			session_lifetime_minutes: g.session_lifetime_minutes,
			idle_timeout_minutes: g.idle_timeout_minutes,
			allow_file_lists: false
		});
	}
});

test('running gravity shows its output and ends the wait', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/lists?target=i-1');
	await page.getByRole('button', { name: 'Run gravity now' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('keeps blocking with the old lists');
	await confirm.getByRole('button', { name: 'Run gravity' }).click();

	const panel = page.getByRole('region', { name: 'Gravity update' });
	await expect(panel.getByRole('log', { name: 'Gravity output' })).toContainText('[✓] Done.');
	await expect(panel.locator('[data-instance="pihole1"]')).toContainText('Done: 123,456 domains');
	await expect(page.getByText('Gravity updated on pihole1.')).toBeVisible();
	await expect(panel).toContainText('Finished');
	// The button says gravity is running while it does, and is usable again once it has finished, without a reload.
	await expect(page.getByRole('button', { name: 'Run gravity', exact: true })).toBeEnabled();
	// The lists were read again: new.txt has been downloaded, so nothing waits.
	await expect(row(page, 'block/https://lists.example/new.txt')).toContainText('Updated');
	await expect(page.getByText(/waiting for a gravity update/)).toHaveCount(0);

	// Closing the panel only hides it.
	await panel.getByRole('button', { name: 'Close the gravity panel' }).click();
	await expect(panel).toBeHidden();

	// A run whose panel was closed while it ran still turns the button back on when it ends.
	await page.getByRole('button', { name: 'Run gravity', exact: true }).click();
	await page.getByRole('alertdialog').getByRole('button', { name: 'Run gravity' }).click();
	await expect(page.getByRole('button', { name: 'Gravity is running…' })).toBeDisabled();
	await page.getByRole('button', { name: 'Close the gravity panel' }).click();
	await expect(page.getByText('Gravity updated on pihole1.').last()).toBeVisible();
	await expect(page.getByRole('button', { name: 'Run gravity', exact: true })).toBeEnabled();
});

// Through a mirrored group of pihole1 and pihole2: each list shows every member's own status, and gravity runs on
// one member at a time. pihole2 has no lists, so its gravity ends with no domains where it had some, which stops the
// run there; the group is made through the API and removed in a finally.
test('a mirrored group shows each member, and gravity rolls through it', async ({ page, state }) => {
	const [one, two] = state.seeded.fixture.instances;
	await openAs(page, state.seeded.fixture.admin, '/dashboard');
	const res = await apiWrite(page, 'POST', '/api/v1/instance-groups', {
		name: 'e2e lists',
		mode: 'mirrored',
		members: [one.id, two.id],
		primary_instance_id: one.id
	});
	const id = (await res.json()).id;
	try {
		await page.goto(`/lists?target=g-${id}`);
		const r = row(page, ads);
		await expect(r).toContainText('pihole2: not subscribed');
		await page.getByRole('button', { name: "Show each member's status for https://lists.example/ads.txt" }).click();
		const members = page.getByRole('list', { name: "Each member's status for https://lists.example/ads.txt" });
		await expect(members).toContainText('pihole1');
		await expect(members).toContainText('Primary');
		await expect(members).toContainText('Not subscribed: see Drift.');

		await page.getByRole('button', { name: 'Run gravity', exact: true }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm).toContainText('one at a time, the primary first');
		await confirm.getByRole('button', { name: 'Run gravity' }).click();
		const panel = page.getByRole('region', { name: 'Gravity update' });
		await expect(panel).toContainText('Finished');
		await expect(panel.locator('[data-instance="pihole1"]')).toContainText('Done');
		await expect(panel.locator('[data-instance="pihole2"]')).toContainText('ended with no domains');
		await expect(panel.getByRole('log', { name: 'Gravity output' })).toContainText('pihole1: ');
		await expect(page.getByText('Gravity updated on pihole1; failed on pihole2.')).toBeVisible();
	} finally {
		await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${id}`);
	}
});
