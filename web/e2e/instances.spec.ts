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

async function addInstance(page: Page, fields: { name: string; url: string; env?: string; password?: string }) {
	await page.getByRole('button', { name: 'Add an instance' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill(fields.name);
	await dialog.getByLabel('Base URL').fill(fields.url);
	if (fields.password !== undefined) await fillPassword(page, fields.password);
	if (fields.env !== undefined) await dialog.getByLabel('Env name').fill(fields.env);
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog).toHaveCount(0);
}

// fillPassword types a password twice into the open dialog, as every form that sets one asks.
async function fillPassword(page: Page, password: string) {
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('App password', { exact: true }).fill(password);
	await dialog.getByLabel('App password again', { exact: true }).fill(password);
}

async function deleteInstance(page: Page, name: string) {
	await action(page, name, 'Delete');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText(`${name} deleted.`)).toBeVisible();
	await expect(row(page, name)).toHaveCount(0);
}

test('lists the instances with their status and where each password comes from', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/instances');
	await expect(page).toHaveTitle('Instances · pihole-rbac');
	await expect(page.locator('tbody tr td:first-child')).toHaveText(['pihole1', 'pihole2', 'pihole3']);

	const one = row(page, 'pihole1');
	await expect(one).toContainText(state.seeded.fixture.instances[0].base_url);
	await expect(one).toContainText('Environment');
	await expect(one).toContainText('PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD');

	// A password from the environment is changed there, not here.
	await page.getByRole('button', { name: 'Actions for pihole1' }).click();
	await expect(page.getByRole('menuitem', { name: 'Edit' })).toBeVisible();
	await expect(page.getByRole('menuitem', { name: 'Change password' })).toHaveCount(0);
	await page.keyboard.press('Escape');

	// Testing the one nobody answers for says so, and leaves it listed.
	await action(page, 'pihole3', 'Test connection');
	await expect(page.getByRole('alert')).toContainText('pihole3: connection test failed');
});

test('an instance without a password is added, but enabling it is refused', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/instances');
	await page.getByRole('button', { name: 'Add an instance' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill('Lab box 7');

	// Caught before sending.
	await dialog.getByLabel('Base URL').fill('https://lab7.example/admin');
	await expect(dialog.getByText('without /admin or /api')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	await dialog.getByLabel('Base URL').fill('https://lab7.example');
	await dialog.getByLabel('App password', { exact: true }).fill('one thing');
	await dialog.getByLabel('App password again', { exact: true }).fill('another');
	await expect(dialog.getByText("The two passwords don't match.")).toBeVisible();
	await dialog.getByLabel('App password', { exact: true }).fill('');
	await dialog.getByLabel('App password again', { exact: true }).fill('');

	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText('Lab box 7 added. Store its password, then enable it.')).toBeVisible();

	const lab = row(page, 'Lab box 7');
	await expect(lab).toContainText('Disabled');
	await expect(lab).toContainText('Missing');

	await action(page, 'Lab box 7', 'Enable');
	await expect(page.getByRole('alert')).toContainText("Couldn't enable Lab box 7");
	await expect(lab).toContainText('Disabled');

	await deleteInstance(page, 'Lab box 7');
});

test('a stored password: added, used, and changed', async ({ page, state }) => {
	const { fixture } = state.seeded;
	await openAs(page, fixture.admin, '/admin/instances');
	await addInstance(page, { name: 'vault', url: fixture.instances[1].base_url, password: fixture.pihole_password });
	await expect(page.getByText("vault added. Enable it when you're ready.")).toBeVisible();
	const vault = row(page, 'vault');
	await expect(vault).toContainText('Stored');
	await expect(vault).toContainText('by admin');

	await action(page, 'vault', 'Enable');
	await expect(page.getByText('vault enabled.')).toBeVisible();

	// A password the Pi-hole refuses isn't stored, and the dialog stays open to say so.
	await action(page, 'vault', 'Change password');
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('New app password', { exact: true }).fill('not it');
	await dialog.getByLabel('New app password again', { exact: true }).fill('not it');
	await dialog.getByRole('button', { name: 'Store password' }).click();
	await expect(dialog.getByRole('alert')).toContainText('refused the app password');
	await dialog.getByLabel('New app password', { exact: true }).fill(fixture.pihole_password);
	await dialog.getByLabel('New app password again', { exact: true }).fill(fixture.pihole_password);
	await dialog.getByRole('button', { name: 'Store password' }).click();
	await expect(page.getByText('New password stored for vault.')).toBeVisible();
	await expect(dialog).toHaveCount(0);

	// Moving it asks for the password again before anything is sent to the new address.
	await action(page, 'vault', 'Edit');
	await dialog.getByLabel('Base URL').fill('http://127.0.0.1:1');
	await expect(dialog).toContainText('Enter the password again to use the new address');
	await expect(dialog.getByText('Enter the password.')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled();
	await dialog.getByRole('button', { name: 'Cancel' }).click();

	await deleteInstance(page, 'vault');
});

test('adding, enabling, renaming, disabling and deleting an instance', async ({ page, state }) => {
	const { fixture } = state.seeded;
	await openAs(page, fixture.admin, '/admin/instances');

	// The spare variable is set, so using it needs its password: the server asks, and the form shows the fields.
	await page.getByRole('button', { name: 'Add an instance' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill('spare');
	await dialog.getByLabel('Base URL').fill(fixture.instances[1].base_url);
	await dialog.getByLabel('Env name').fill(fixture.spare_env_name);
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog.getByRole('alert')).toContainText('is set, so enter the password it holds');
	await fillPassword(page, fixture.pihole_password);
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText("spare added. Enable it when you're ready.")).toBeVisible();
	await expect(row(page, 'spare')).toContainText('Environment');

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

	// A rename doesn't change how it connects, so it saves without a test or a password.
	await action(page, 'spare', 'Edit');
	await expect(dialog.getByLabel('Env name')).toHaveValue(fixture.spare_env_name);
	await expect(dialog.getByLabel('App password', { exact: true })).toHaveCount(0);
	await dialog.getByLabel('Name', { exact: true }).fill('spare renamed');
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('spare renamed saved.')).toBeVisible();

	// A new address for an enabled instance needs the password, is tested first, and is refused if the test fails.
	await action(page, 'spare renamed', 'Edit');
	await expect(dialog).toBeVisible();
	await dialog.getByLabel('Base URL').fill('http://127.0.0.1:1');
	await expect(dialog).toContainText('tested before they\'re saved');
	await fillPassword(page, fixture.pihole_password);
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
