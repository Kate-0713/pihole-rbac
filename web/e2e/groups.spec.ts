// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The instance groups page, against the seeded server. The seeded server has no groups; each test removes the groups
// and roles it adds, since the roles page's tests list every group in the grant editor.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const row = (page: Page, name: string) => page.getByRole('row').filter({ has: page.getByRole('cell', { name, exact: true }) });

async function action(page: Page, name: string, item: string) {
	await page.getByRole('button', { name: `Actions for ${name}` }).click();
	await page.getByRole('menuitem', { name: item }).click();
}

async function choose(page: Page, label: string, option: string) {
	await page.getByRole('dialog').getByRole('combobox', { name: label }).click();
	await page.getByRole('option', { name: option, exact: true }).click();
}

test('a mirrored group is added, changed to independent and deleted', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/groups');
	await expect(page).toHaveTitle('Groups · pihole-rbac');
	await expect(page.getByText('No groups yet.')).toBeVisible();

	await page.getByRole('button', { name: 'Add a group' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill('e2e mirror');
	await choose(page, 'Mode', 'Mirrored');
	// A mirrored group needs a primary among its members.
	// Once the form has been typed in, its hints show and Add waits until they're dealt with.
	await expect(dialog.getByRole('combobox', { name: 'Primary' })).toBeDisabled();
	await expect(dialog.getByText('A mirrored group needs at least one member, its primary.')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	// The first member becomes the primary; another can be chosen once there are more.
	await dialog.getByRole('checkbox', { name: 'pihole1' }).check();
	await expect(dialog.getByRole('combobox', { name: 'Primary' })).toHaveText('pihole1');
	await dialog.getByRole('checkbox', { name: 'pihole2' }).check();
	await choose(page, 'Primary', 'pihole2');
	// Unticking the primary hands the role back to the one member left.
	await dialog.getByRole('checkbox', { name: 'pihole2' }).uncheck();
	await expect(dialog.getByRole('combobox', { name: 'Primary' })).toHaveText('pihole1');
	await dialog.getByRole('checkbox', { name: 'pihole2' }).check();
	await choose(page, 'Primary', 'pihole2');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog).toHaveCount(0);
	await expect(page.getByText('e2e mirror added.')).toBeVisible();

	const mirror = row(page, 'e2e mirror');
	await expect(mirror).toContainText('Mirrored');
	await expect(mirror.getByRole('listitem')).toHaveText(['pihole2 · primary', 'pihole1']);

	// pihole1 is now in a mirrored group, so another mirrored group can't take it; an independent one can.
	await page.getByRole('button', { name: 'Add a group' }).click();
	await dialog.getByLabel('Name', { exact: true }).fill('E2E Mirror');
	await choose(page, 'Mode', 'Mirrored');
	await expect(dialog.getByRole('checkbox', { name: 'pihole1' })).toBeDisabled();
	await expect(dialog.getByText('In the mirrored group "e2e mirror"').first()).toBeVisible();
	await expect(dialog.getByText('There is already a group called "e2e mirror".')).toBeVisible();
	await choose(page, 'Mode', 'Independent');
	await expect(dialog.getByRole('checkbox', { name: 'pihole1' })).toBeEnabled();
	await dialog.getByRole('button', { name: 'Cancel' }).click();

	// Independent, without pihole2: the primary goes with the mode.
	await action(page, 'e2e mirror', 'Edit');
	await dialog.getByLabel('Name', { exact: true }).fill('e2e labels');
	await choose(page, 'Mode', 'Independent');
	await expect(dialog.getByRole('combobox', { name: 'Primary' })).toHaveCount(0);
	await dialog.getByRole('checkbox', { name: 'pihole2' }).uncheck();
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(dialog).toHaveCount(0);
	const labels = row(page, 'e2e labels');
	await expect(labels).toContainText('Independent');
	await expect(labels.getByRole('listitem')).toHaveText(['pihole1']);

	await action(page, 'e2e labels', 'Delete');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText('e2e labels deleted.')).toBeVisible();
	await expect(row(page, 'e2e labels')).toHaveCount(0);
});

test("the server's refusals are shown in the dialogs", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/groups');
	const [one, two] = state.seeded.fixture.instances;
	const group = await (
		await apiWrite(page, 'POST', '/api/v1/instance-groups', {
			name: 'e2e watched',
			mode: 'mirrored',
			members: [one.id, two.id],
			primary_instance_id: one.id
		})
	).json();
	const role = await (
		await apiWrite(page, 'POST', '/api/v1/roles', {
			name: 'e2e drift watchers',
			grants: [{ permission: 'drift.view', scope: 'group', id: group.id }]
		})
	).json();
	await page.reload();

	// A role holds a drift permission on it, so it can't become independent, or be deleted.
	await action(page, 'e2e watched', 'Edit');
	const dialog = page.getByRole('dialog');
	await choose(page, 'Mode', 'Independent');
	await expect(dialog.getByText("can't become independent while a role holds drift permissions")).toBeVisible();
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(dialog.getByRole('alert')).toContainText('e2e drift watchers');
	await dialog.getByRole('button', { name: 'Cancel' }).click();

	await action(page, 'e2e watched', 'Delete');
	const confirm = page.getByRole('alertdialog');
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(confirm.getByRole('alert')).toContainText('e2e drift watchers');
	await confirm.getByRole('button', { name: 'Cancel' }).click();

	await apiWrite(page, 'DELETE', `/api/v1/roles/${role.id}`);
	await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${group.id}`);
});

test('the page needs instances.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.role_lead, '/admin/groups');
	await expect(page.getByText('You need the instances.manage permission to manage groups.')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Add a group' })).toHaveCount(0);
	await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Admin' }).click();
	await expect(page.getByRole('menuitem', { name: 'Roles' })).toBeVisible();
	await expect(page.getByRole('menuitem', { name: 'Groups' })).toHaveCount(0);
});
