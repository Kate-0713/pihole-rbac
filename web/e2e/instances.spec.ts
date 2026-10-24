// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The instances page, against the seeded server: pihole1 and pihole2 on the fake Pi-holes, pihole3 on an address
// nothing listens on. Tests never change those three, since the other pages' tests rely on them; they add their own
// instances and delete them again.
import type { Page } from '@playwright/test';
import { expect, openAs, picker, test } from './fixtures.js';

const row = (page: Page, name: string) => page.getByRole('row').filter({ has: page.getByRole('cell', { name, exact: true }) });

async function action(page: Page, name: string, item: string) {
	await page.getByRole('button', { name: `Actions for ${name}` }).click();
	await page.getByRole('menuitem', { name: item }).click();
}

async function addInstance(page: Page, fields: { name: string; url: string; env?: string }) {
	await page.getByRole('button', { name: 'Add an instance' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill(fields.name);
	await dialog.getByLabel('Base URL').fill(fields.url);
	if (fields.env !== undefined) await dialog.getByLabel('Env name').fill(fields.env);
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog).toHaveCount(0);
}

async function deleteInstance(page: Page, name: string) {
	await action(page, name, 'Delete');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText(`${name} deleted.`)).toBeVisible();
	await expect(row(page, name)).toHaveCount(0);
}

test('lists the instances with their status and password variable', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/instances');
	await expect(page).toHaveTitle('Instances · pihole-rbac');
	await expect(page.locator('tbody tr td:first-child')).toHaveText(['pihole1', 'pihole2', 'pihole3']);

	const one = row(page, 'pihole1');
	await expect(one).toContainText(state.seeded.fixture.instances[0].base_url);
	await expect(one).toContainText('Set');
	await expect(one).toContainText('PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD');

	// Testing the one nobody answers for says so, and leaves it listed.
	await action(page, 'pihole3', 'Test connection');
	await expect(page.getByRole('alert')).toContainText('pihole3: connection test failed');
});

test('an instance without its password variable is added, but enabling it is refused', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/instances');
	await page.getByRole('button', { name: 'Add an instance' }).click();
	const dialog = page.getByRole('dialog');

	// The env name follows the name, and the hint names the variable.
	await dialog.getByLabel('Name', { exact: true }).fill('Lab box 7');
	await expect(dialog.getByLabel('Env name')).toHaveValue('LAB_BOX_7');
	await expect(dialog).toContainText('PIHOLE_RBAC_INSTANCE_LAB_BOX_7_PASSWORD');

	// Caught before sending.
	await dialog.getByLabel('Base URL').fill('https://lab7.example/admin');
	await expect(dialog.getByText('without /admin or /api')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();

	await dialog.getByLabel('Base URL').fill('https://lab7.example');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText('Lab box 7 added. Set PIHOLE_RBAC_INSTANCE_LAB_BOX_7_PASSWORD')).toBeVisible();

	const lab = row(page, 'Lab box 7');
	await expect(lab).toContainText('Disabled');
	await expect(lab).toContainText('Missing');

	await action(page, 'Lab box 7', 'Enable');
	await expect(page.getByRole('alert')).toContainText("Couldn't enable Lab box 7");
	await expect(lab).toContainText('Disabled');

	await deleteInstance(page, 'Lab box 7');
});

test('adding, enabling, renaming, disabling and deleting an instance', async ({ page, state }) => {
	const { fixture } = state.seeded;
	await openAs(page, fixture.admin, '/admin/instances');
	await addInstance(page, { name: 'spare', url: fixture.instances[1].base_url, env: fixture.spare_env_name });
	await expect(page.getByText("spare added. Enable it when you're ready.")).toBeVisible();

	await action(page, 'spare', 'Test connection');
	await expect(page.getByText('spare: the connection works.')).toBeVisible();

	await action(page, 'spare', 'Enable');
	await expect(page.getByText('spare enabled.')).toBeVisible();
	await expect(row(page, 'spare')).not.toContainText('Disabled');

	// Enabled instances are offered in the picker on the other pages.
	await page.getByRole('link', { name: 'Dashboard' }).click();
	await picker(page).click();
	await expect(page.getByRole('option', { name: /spare/ })).toBeVisible();
	await page.keyboard.press('Escape');
	await page.goto('/admin/instances');

	// A rename doesn't change how it connects, so it saves without a test.
	await action(page, 'spare', 'Edit');
	const dialog = page.getByRole('dialog');
	await expect(dialog.getByLabel('Env name')).toHaveValue(fixture.spare_env_name);
	await dialog.getByLabel('Name', { exact: true }).fill('spare renamed');
	await expect(dialog.getByLabel('Env name')).toHaveValue(fixture.spare_env_name);
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('spare renamed saved.')).toBeVisible();

	// A change to the address of an enabled instance is tested first, and refused if the test fails.
	await action(page, 'spare renamed', 'Edit');
	await expect(dialog).toBeVisible();
	await dialog.getByLabel('Base URL').fill('http://127.0.0.1:1');
	await expect(dialog).toContainText('tested before they\'re saved');
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(dialog.getByRole('alert')).toBeVisible();
	await dialog.getByRole('button', { name: 'Cancel' }).click();
	await expect(row(page, 'spare renamed')).toContainText(fixture.instances[1].base_url);

	await action(page, 'spare renamed', 'Disable');
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('Nobody can use this Pi-hole');
	await confirm.getByRole('button', { name: 'Disable' }).click();
	await expect(page.getByText('spare renamed disabled.')).toBeVisible();
	await expect(row(page, 'spare renamed')).toContainText('Disabled');

	await deleteInstance(page, 'spare renamed');
});

test("an instance a role refers to can't be deleted, and the dialog says why", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/instances');
	await action(page, 'pihole1', 'Delete');
	const confirm = page.getByRole('alertdialog');
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(confirm.getByRole('alert')).toContainText('e2e-one-instance');
	await confirm.getByRole('button', { name: 'Cancel' }).click();
	await expect(row(page, 'pihole1')).toHaveCount(1);
});

test("a user without instances.manage isn't offered the page and can't use it", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/admin/instances');
	await expect(page.getByText('You need the instances.manage permission')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Add an instance' })).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Admin' })).toHaveCount(0);
});
