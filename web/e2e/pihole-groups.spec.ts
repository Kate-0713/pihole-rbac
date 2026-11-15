// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The Pi-hole groups page, against the seeded server. pihole1's fake Pi-hole starts with Default and kids (see the
// e2e server), with games.example and school.example and the client 10.0.1.5 in kids. Tests that add a group delete
// it, and tests that change one put it back, so they don't depend on order.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const row = (page: Page, name: string) => page.locator(`tr[data-group="${name}"]`);

test('lists the groups, with the Default group marked', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/pihole-groups?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Pi-hole groups · pihole-rbac');
	await expect(row(page, 'Default')).toContainText('Default');
	await expect(row(page, 'Default')).toContainText('Enabled');
	await expect(row(page, 'kids')).toBeVisible();
	// Default can't be deleted, so it has no Delete.
	await expect(page.getByRole('button', { name: 'Delete Default' })).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Delete kids' })).toBeVisible();
});

test('a user with only view permissions sees the groups but no changes', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await page.getByRole('link', { name: 'Pi-hole groups' }).click();
	await expect(row(page, 'kids')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Add a Pi-hole group' })).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Change kids' })).toHaveCount(0);
});

test('adding, renaming, disabling and deleting a group', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/pihole-groups?target=i-1');
	await page.getByRole('button', { name: 'Add a Pi-hole group' }).click();
	const dialog = page.getByRole('dialog');
	// The name rules are checked as you type, and Add waits until the name is fixed.
	await dialog.getByLabel('Name').fill(' e2e lab');
	await expect(dialog.getByText("A name can't start or end with a space.")).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	await dialog.getByLabel('Name').fill('e2e lab');
	await dialog.getByLabel('Comment').fill('added by e2e');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText('e2e lab added on pihole1.')).toBeVisible();
	await expect(row(page, 'e2e lab')).toContainText('added by e2e');

	try {
		await page.getByRole('button', { name: 'Change e2e lab' }).click();
		await dialog.getByLabel('Name').fill('e2e night');
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('e2e night saved on pihole1.')).toBeVisible();
		await expect(row(page, 'e2e night')).toBeVisible();
		await expect(row(page, 'e2e lab')).toHaveCount(0);

		await page.getByRole('button', { name: 'Disable e2e night' }).click();
		await expect(page.getByText('e2e night disabled on pihole1.')).toBeVisible();
		await expect(row(page, 'e2e night')).toContainText('Disabled');
		await page.getByRole('button', { name: 'Enable e2e night' }).click();
		await expect(row(page, 'e2e night')).toContainText('Enabled');

		// Delete says what's in the group first; Cancel keeps it.
		await page.getByRole('button', { name: 'Delete e2e night' }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm.locator('[data-usage]')).toContainText('0 domains, 0 clients and 0 lists');
		await confirm.getByRole('button', { name: 'Cancel' }).click();
		await expect(row(page, 'e2e night')).toBeVisible();
		await page.getByRole('button', { name: 'Delete e2e night' }).click();
		await confirm.getByRole('button', { name: 'Delete' }).click();
		await expect(page.getByText('e2e night deleted on pihole1.')).toBeVisible();
		await expect(row(page, 'e2e night')).toHaveCount(0);
	} finally {
		for (const name of ['e2e lab', 'e2e night']) {
			const res = await page.request.get(`/api/v1/targets/i-1/groups`);
			const { groups } = (await res.json()) as { groups: { name: string }[] };
			if (groups.some((g) => g.name === name)) await apiWrite(page, 'DELETE', '/api/v1/targets/i-1/groups', { name });
		}
	}
});

test('the delete dialog says what uses a group', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/pihole-groups?target=i-1');
	await page.getByRole('button', { name: 'Delete kids' }).click();
	const confirm = page.getByRole('alertdialog');
	// games.example and school.example, and the printer.
	await expect(confirm.locator('[data-usage]')).toContainText('2 domains, 1 client and 0 lists');
	await confirm.getByRole('button', { name: 'Cancel' }).click();
	await expect(row(page, 'kids')).toBeVisible();
});

test('disabling the Default group asks first', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/pihole-groups?target=i-1');
	await row(page, 'Default').getByRole('button', { name: 'Disable Default' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('turns filtering off');
	await confirm.getByRole('button', { name: 'Cancel' }).click();
	await expect(row(page, 'Default')).toContainText('Enabled');

	try {
		await row(page, 'Default').getByRole('button', { name: 'Disable Default' }).click();
		await confirm.getByRole('button', { name: 'Disable Default' }).click();
		await expect(page.getByText('Default disabled on pihole1.')).toBeVisible();
		await expect(row(page, 'Default')).toContainText('Disabled');
		// Turning it back on needs no confirming.
		await page.getByRole('button', { name: 'Enable Default' }).click();
		await expect(row(page, 'Default')).toContainText('Enabled');
	} finally {
		await apiWrite(page, 'PATCH', '/api/v1/targets/i-1/groups', { name: 'Default', enabled: true });
	}
	// The Default group's name can't be changed.
	await page.getByRole('button', { name: 'Change Default' }).click();
	await expect(page.getByRole('dialog').getByLabel('Name')).toBeDisabled();
});

test('renaming a group the app refers to lists the references, and they follow', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/pihole-groups?target=i-1');
	await apiWrite(page, 'POST', '/api/v1/targets/i-1/groups', { name: 'e2e ref', enabled: true });
	await apiWrite(page, 'PUT', '/api/v1/client-reset/rules', {
		rules: [{ scope: 'instance', id: 1, comment_prefix: 'E2E-', group_match: 'names', pihole_groups: ['e2e ref'] }]
	});
	try {
		await page.reload();
		await page.getByRole('button', { name: 'Change e2e ref' }).click();
		const dialog = page.getByRole('dialog');
		await dialog.getByLabel('Name').fill('e2e renamed');
		await dialog.getByRole('button', { name: 'Save' }).click();
		// The server asked for confirmation; the dialog lists the reference and offers to go ahead.
		await expect(dialog).toContainText('The app refers to e2e ref');
		await expect(dialog.locator('[data-references]')).toContainText('1 client reset rule');
		await expect(dialog.locator('[data-references]')).toContainText('Client reset rule E2E- on pihole1, groups: e2e ref');
		await dialog.getByRole('button', { name: 'Rename anyway' }).click();
		await expect(page.getByText('References: 1 client reset rule updated.')).toBeVisible();
		await expect(row(page, 'e2e renamed')).toBeVisible();

		const rules = await (await page.request.get('/api/v1/client-reset/rules')).json();
		expect(rules.rules[0].pihole_groups).toEqual(['e2e renamed']);

		// Deleting it says the app still refers to it, and leaves the rule alone.
		await page.getByRole('button', { name: 'Delete e2e renamed' }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm.locator('[data-references]')).toContainText('1 client reset rule');
		await confirm.getByRole('button', { name: 'Delete' }).click();
		await expect(page.getByText('e2e renamed deleted on pihole1.')).toBeVisible();
		const after = await (await page.request.get('/api/v1/client-reset/rules')).json();
		expect(after.rules[0].pihole_groups).toEqual(['e2e renamed']);
	} finally {
		await apiWrite(page, 'PUT', '/api/v1/client-reset/rules', { rules: [] });
		const { groups } = (await (await page.request.get('/api/v1/targets/i-1/groups')).json()) as { groups: { name: string }[] };
		for (const name of ['e2e ref', 'e2e renamed']) {
			if (groups.some((g) => g.name === name)) await apiWrite(page, 'DELETE', '/api/v1/targets/i-1/groups?confirm=true', { name });
		}
	}
});
