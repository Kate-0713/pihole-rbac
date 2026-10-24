// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The users page and changing your own password, against the seeded server. Its users: admin, alice, bob, carol and
// dave (users.manage and domains.view through the editable role e2e-user-lead). Tests that create a user delete it,
// and the one where dave disables his own account has admin enable it again.
import type { Browser, Page } from '@playwright/test';
import { apiWrite, expect, logIn, openAs, test, type State, type User } from './fixtures.js';

// The table row whose username is exactly `username` (the cell also holds a "You" badge and notes).
const row = (page: Page, username: string) =>
	page.getByRole('row').filter({ has: page.locator('td span.font-medium', { hasText: new RegExp(`^${username}$`) }) });

async function actions(page: Page, username: string) {
	await page.getByRole('button', { name: `Actions for ${username}`, exact: true }).click();
	return page.getByRole('menu');
}

// withPage runs fn in a separate browser context logged in as user.
async function withPage(browser: Browser, state: State, user: User, fn: (page: Page) => Promise<void>) {
	const context = await browser.newContext({ baseURL: state.seeded.url });
	const page = await context.newPage();
	await page.goto('/login');
	await logIn(page, user);
	await expect(page).not.toHaveURL(/\/login/);
	await fn(page);
	await context.close();
}

// userID finds a user's ID through the API, for setting things up and tidying them away.
async function userID(page: Page, username: string): Promise<number> {
	const res = await page.request.get('/api/v1/users');
	expect(res.ok()).toBe(true);
	const { users } = (await res.json()) as { users: { id: number; username: string }[] };
	const u = users.find((x) => x.username === username);
	if (!u) throw new Error(`no user ${username}`);
	return u.id;
}

async function roleID(page: Page, name: string): Promise<number> {
	const res = await page.request.get('/api/v1/roles');
	expect(res.ok()).toBe(true);
	const { roles } = (await res.json()) as { roles: { id: number; name: string }[] };
	const r = roles.find((x) => x.name === name);
	if (!r) throw new Error(`no role ${name}`);
	return r.id;
}

test('lists the users with their roles', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/users');
	await expect(page).toHaveTitle('Users · pihole-rbac');

	const admin = row(page, 'admin');
	await expect(admin).toContainText('You');
	await expect(admin).toContainText('Local');
	await expect(admin).toContainText('Enabled');
	// The admin logged in just now, so there is a last login.
	await expect(admin).not.toContainText('Never');
	await expect(row(page, 'alice')).toContainText('e2e-one-instance');
	await expect(row(page, 'dave')).toContainText('e2e-user-lead');
});

test('creating a user, changing their roles and password, disabling and deleting them', async ({
	page,
	state,
	browser
}) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/users');
	await page.getByRole('button', { name: 'New user' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Username').fill('Erin');
	await dialog.getByLabel('Password', { exact: true }).fill('erin-first-password');
	await dialog.getByLabel('Password again').fill('erin-first-passwrod');
	// The form checks as you type, so the mismatch shows at once and the button waits for it to be fixed.
	await expect(dialog.getByText("The passwords don't match.")).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Create user' })).toBeDisabled();
	await dialog.getByLabel('Password again').fill('erin-first-password');
	await dialog.getByRole('checkbox', { name: 'reader' }).click();
	await dialog.getByRole('button', { name: 'Create user' }).click();
	await expect(page.getByText('User erin created.')).toBeVisible();
	await expect(row(page, 'erin')).toContainText('reader');
	await expect(row(page, 'erin')).toContainText('Never');

	// Erin can log in.
	const erin = { username: 'erin', password: 'erin-first-password', about: '' };
	await withPage(browser, state, erin, async (p) => {
		await expect(p.getByRole('button', { name: 'Account: erin' })).toBeVisible();
	});

	await (await actions(page, 'erin')).getByRole('menuitem', { name: 'Change roles' }).click();
	const roles = page.getByRole('dialog');
	await expect(roles.getByRole('button', { name: 'Save' })).toBeDisabled(); // nothing changed yet
	await roles.getByRole('checkbox', { name: 'staff' }).click();
	await roles.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('Roles of erin saved.')).toBeVisible();
	await expect(row(page, 'erin')).toContainText('reader, staff');

	await (await actions(page, 'erin')).getByRole('menuitem', { name: 'Set password' }).click();
	const pw = page.getByRole('dialog');
	await pw.getByLabel('New password', { exact: true }).fill('erin-second-password');
	await pw.getByLabel('New password again').fill('erin-second-password');
	await pw.getByRole('button', { name: 'Set password' }).click();
	await expect(page.getByText('New password set for erin.')).toBeVisible();
	await withPage(browser, state, { ...erin, password: 'erin-second-password' }, async () => {});

	await (await actions(page, 'erin')).getByRole('menuitem', { name: 'Disable' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText("erin is logged out at once and can't log in until enabled again");
	await confirm.getByRole('button', { name: 'Disable' }).click();
	await expect(page.getByText('erin disabled.')).toBeVisible();
	await expect(row(page, 'erin')).toContainText('Disabled');

	await (await actions(page, 'erin')).getByRole('menuitem', { name: 'Enable' }).click();
	await expect(page.getByText('erin enabled.')).toBeVisible();
	await expect(row(page, 'erin')).toContainText('Enabled');

	await (await actions(page, 'erin')).getByRole('menuitem', { name: 'Delete' }).click();
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText('erin deleted.')).toBeVisible();
	await expect(row(page, 'erin')).toHaveCount(0);
});

test('someone who manages users can only give the roles they hold, and only manage users below them', async ({
	page,
	state
}) => {
	await openAs(page, state.seeded.fixture.user_lead, '/admin/users');
	// admin holds more than dave, so dave can't change it: no actions, and a note saying why.
	await expect(row(page, 'admin')).toContainText("Holds permissions you don't");
	await expect(page.getByRole('button', { name: 'Actions for admin' })).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Actions for dave' })).toBeVisible();

	await page.getByRole('button', { name: 'New user' }).click();
	const dialog = page.getByRole('dialog');
	await expect(dialog.getByRole('checkbox', { name: 'admin' })).toBeDisabled();
	await expect(dialog.getByRole('checkbox', { name: 'e2e-user-lead' })).toBeEnabled();
});

test('disabling your own account asks first and logs you out', async ({ page, state, browser }) => {
	const dave = state.seeded.fixture.user_lead;
	await openAs(page, dave, '/admin/users');
	await (await actions(page, 'dave')).getByRole('menuitem', { name: 'Disable' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('Disable your own account?');
	await confirm.getByRole('button', { name: 'Disable' }).click();
	// The server asks for confirmation, and the dialog shows it.
	await expect(confirm).toContainText('This would disable your own account');
	await confirm.getByRole('button', { name: 'Yes, disable my account' }).click();
	await expect(page).toHaveURL(/\/login/);

	// Enable dave again for the other tests.
	await withPage(browser, state, state.seeded.fixture.admin, async (admin) => {
		const id = await userID(admin, 'dave');
		await apiWrite(admin, 'POST', `/api/v1/users/${id}/enable`);
	});
	await logIn(page, dave);
	await expect(page).not.toHaveURL(/\/login/);
});

test('changing your own password from the account menu', async ({ page, state, browser }) => {
	// A user of its own, so a changed password can't upset other tests.
	await withPage(browser, state, state.seeded.fixture.admin, async (admin) => {
		const reader = await roleID(admin, 'reader');
		await apiWrite(admin, 'POST', '/api/v1/users', {
			username: 'frank',
			password: 'frank-first-password',
			role_ids: [reader]
		});
	});
	const frank = { username: 'frank', password: 'frank-first-password', about: '' };
	await openAs(page, frank, '/');

	await page.getByRole('button', { name: 'Account: frank' }).click();
	await page.getByRole('menuitem', { name: 'Change password' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Current password').fill('not-my-password');
	await dialog.getByLabel('New password', { exact: true }).fill('frank-second-password');
	await dialog.getByLabel('New password again').fill('frank-second-password');
	await dialog.getByRole('button', { name: 'Change password' }).click();
	// A wrong current password is a 401, but not one that logs you out.
	await expect(dialog.getByRole('alert')).toContainText('Your current password is wrong.');
	await expect(page).not.toHaveURL(/\/login/);

	await dialog.getByLabel('Current password').fill('frank-first-password');
	await dialog.getByRole('button', { name: 'Change password' }).click();
	await expect(page.getByText('Password changed. Your other sessions have been logged out.')).toBeVisible();

	// The new password works; tidy up.
	await withPage(browser, state, { ...frank, password: 'frank-second-password' }, async () => {});
	await withPage(browser, state, state.seeded.fixture.admin, async (admin) => {
		await apiWrite(admin, 'DELETE', `/api/v1/users/${await userID(admin, 'frank')}`);
	});
});

test('the users page needs users.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.no_instances, '/admin/users');
	await expect(page.getByText('You need the users.manage permission')).toBeVisible();
});
