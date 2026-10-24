// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The roles pages, against the seeded server. Its roles: the builtin admin, the starter roles staff and reader, and
// the fixture's e2e-one-instance (alice), e2e-no-instances (bob) and e2e-role-lead (carol: roles.manage and
// domains.view). Tests that create a role delete it, and the one that takes carol's roles.manage away gives it back.
import type { Browser, Page } from '@playwright/test';
import { expect, logIn, openAs, test, type State } from './fixtures.js';

const row = (page: Page, name: string) => page.getByRole('row').filter({ has: page.getByRole('link', { name, exact: true }) });

// grant finds one checkbox of the grant editor: a permission's row, then the box labelled with a scope.
const grant = (page: Page, permission: string, scope: string) =>
	page.getByRole('group', { name: permission, exact: true }).getByRole('checkbox', { name: scope, exact: true });

// asAdmin runs fn in a separate browser context logged in as admin, for setting things up or putting them back.
async function asAdmin(browser: Browser, state: State, fn: (page: Page) => Promise<void>) {
	const context = await browser.newContext({ baseURL: state.seeded.url });
	const page = await context.newPage();
	await page.goto('/login');
	await logIn(page, state.seeded.fixture.admin);
	await expect(page).not.toHaveURL(/\/login/);
	await fn(page);
	await context.close();
}

test('lists the roles with their permissions and who has them', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/roles');
	await expect(page).toHaveTitle('Roles · pihole-rbac');

	const admin = row(page, 'admin');
	await expect(admin).toContainText('Builtin');
	await expect(admin).toContainText('Every permission, everywhere');
	await expect(admin.getByRole('button', { name: 'Delete admin' })).toHaveCount(0);

	const one = row(page, 'e2e-one-instance');
	await expect(one).toContainText('domains.view: pihole1');
	await expect(one).toContainText('alice');
	await expect(row(page, 'e2e-no-instances')).toContainText('audit.view');
	await expect(row(page, 'staff')).toContainText('clients.edit: all instances');
	await expect(row(page, 'staff')).toContainText('Nobody');
});

test('creating, changing and deleting a role', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/roles');
	await page.getByRole('link', { name: 'New role', exact: true }).click();
	await expect(page).toHaveURL('/admin/roles/new');
	await expect(page).toHaveTitle('New role · pihole-rbac');

	await page.getByLabel('Name').fill('night shift');
	await page.getByLabel('Description (optional)').fill('Covers the evenings');
	await grant(page, 'domains.view', 'pihole1').click();
	await grant(page, 'domains.view', 'pihole2').click();
	await grant(page, 'blocking.toggle', 'All instances').click();
	// All covers every instance, so the separate boxes are ticked and can't be changed.
	await expect(grant(page, 'blocking.toggle', 'pihole3')).toBeChecked();
	await expect(grant(page, 'blocking.toggle', 'pihole3')).toBeDisabled();
	await grant(page, 'audit.view', 'Granted').click();
	await page.getByRole('button', { name: 'Create role' }).click();

	await expect(page.getByText('Role night shift created.')).toBeVisible();
	await expect(page).toHaveURL('/admin/roles');
	const night = row(page, 'night shift');
	await expect(night).toContainText('domains.view: pihole1, pihole2');
	await expect(night).toContainText('blocking.toggle: all instances');
	await expect(night).toContainText('audit.view');
	await expect(night).toContainText('Covers the evenings');

	await night.getByRole('link', { name: 'night shift', exact: true }).click();
	await expect(page).toHaveTitle('night shift · Roles · pihole-rbac');
	await expect(grant(page, 'domains.view', 'pihole2')).toBeChecked();
	// Nothing changed yet, so there's nothing to save.
	await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled();
	await grant(page, 'domains.view', 'pihole2').click();
	await page.getByLabel('Name').fill('late shift');
	await page.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('Role late shift saved.')).toBeVisible();
	await expect(row(page, 'late shift')).toContainText('domains.view: pihole1');
	await expect(row(page, 'late shift')).not.toContainText('pihole2');

	await page.getByRole('button', { name: 'Delete late shift' }).click();
	const confirm = page.getByRole('alertdialog');
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText('Role late shift deleted.')).toBeVisible();
	await expect(row(page, 'late shift')).toHaveCount(0);
});

test('a role in use, and the builtin role, are refused', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/roles');
	await page.getByRole('button', { name: 'Delete e2e-one-instance' }).click();
	const confirm = page.getByRole('alertdialog');
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(confirm.getByRole('alert')).toContainText('still in use');
	await expect(confirm.getByRole('alert')).toContainText('alice');
	await confirm.getByRole('button', { name: 'Cancel' }).click();

	await row(page, 'admin').getByRole('link', { name: 'admin', exact: true }).click();
	await expect(page.getByText("The builtin admin role always holds every permission, and can't be changed.")).toBeVisible();
	await expect(grant(page, 'users.manage', 'Granted')).toBeChecked();
	await expect(grant(page, 'users.manage', 'Granted')).toBeDisabled();
	await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0);
});

test('no one can grant more than they hold', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.role_lead, '/admin/roles/new');
	await page.getByLabel('Name').fill('escalation');
	await grant(page, 'users.manage', 'Granted').click();
	await page.getByRole('button', { name: 'Create role' }).click();
	await expect(page.getByRole('alert')).toContainText("You don't hold: users.manage on all");
	await expect(page).toHaveURL('/admin/roles/new');

	// A role holding more than carol does is shown, but can't be changed or deleted by her.
	await page.goto('/admin/roles');
	await expect(page.getByRole('button', { name: 'Delete e2e-no-instances' })).toHaveCount(0);
	await page.getByRole('link', { name: 'Open e2e-no-instances' }).click();
	await expect(page.getByText("This role holds permissions you don't")).toBeVisible();
});

test('taking away your own roles.manage asks first', async ({ page, state, browser }) => {
	await openAs(page, state.seeded.fixture.role_lead, '/admin/roles');
	await row(page, 'e2e-role-lead').getByRole('link', { name: 'e2e-role-lead', exact: true }).click();
	await grant(page, 'roles.manage', 'Granted').click();
	await page.getByRole('button', { name: 'Save' }).click();

	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('Remove your own access?');
	await expect(confirm).toContainText('roles.manage');
	await confirm.getByRole('button', { name: 'Cancel' }).click();
	// Cancelled: nothing was saved.
	await page.reload();
	await expect(grant(page, 'roles.manage', 'Granted')).toBeChecked();

	await grant(page, 'roles.manage', 'Granted').click();
	await page.getByRole('button', { name: 'Save' }).click();
	await confirm.getByRole('button', { name: 'Go ahead' }).click();
	await expect(page.getByText('Role e2e-role-lead saved.')).toBeVisible();
	// The session's permissions are read again, so the page and the Admin menu follow at once.
	await expect(page.getByText('You need the roles.manage permission')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Admin' })).toHaveCount(0);

	// Put it back for the other tests.
	await asAdmin(browser, state, async (admin) => {
		await admin.goto('/admin/roles');
		await row(admin, 'e2e-role-lead').getByRole('link', { name: 'e2e-role-lead', exact: true }).click();
		await grant(admin, 'roles.manage', 'Granted').click();
		await admin.getByRole('button', { name: 'Save' }).click();
		await expect(admin.getByText('Role e2e-role-lead saved.')).toBeVisible();
	});
});

test('the roles pages need roles.manage, and unknown roles are not found', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/admin/roles');
	await expect(page.getByText('You need the roles.manage permission')).toBeVisible();

	await page.goto('/admin/roles/abc');
	await expect(page.getByRole('heading', { name: "This page doesn't exist" })).toBeVisible();
});

test('a role that no longer exists is the not-found page', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/roles/999');
	await expect(page.getByRole('heading', { name: "This page doesn't exist" })).toBeVisible();
});
