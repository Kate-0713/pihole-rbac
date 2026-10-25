// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The LDAP page, against the seeded server and the fake directory the e2e server starts. LDAP login starts off and
// unconfigured; the test that turns it on turns it off again and removes its mapping. The saved LDAP settings stay,
// which no other test minds.
import type { Browser, Page } from '@playwright/test';
import { apiWrite, expect, logIn, openAs, test, type State, type User } from './fixtures.js';

async function fillServer(page: Page, state: State, password?: string) {
	const d = state.seeded.fixture.ldap;
	await page.getByLabel('Server URL').fill(d.url);
	await page.getByLabel('Bind DN').fill(d.bind_dn);
	if (password !== undefined) await page.getByLabel('Bind password').fill(password);
	await page.getByLabel('Base DN').fill(d.base_dn);
	await page.getByLabel('User filter').fill(d.user_filter);
}

// loginWorks logs in as user in a separate browser context and reports whether it got in.
async function loginWorks(browser: Browser, state: State, user: User): Promise<boolean> {
	const context = await browser.newContext({ baseURL: state.seeded.url });
	const page = await context.newPage();
	await page.goto('/login');
	await logIn(page, user);
	const ok = await page
		.getByRole('button', { name: `Account: ${user.username}` })
		.waitFor({ timeout: 5000 })
		.then(() => true)
		.catch(() => false);
	await context.close();
	return ok;
}

test('setting LDAP up, turning it on, mapping a group, and turning it off', async ({ page, state, browser }) => {
	const d = state.seeded.fixture.ldap;
	await openAs(page, state.seeded.fixture.admin, '/admin/ldap');
	await expect(page).toHaveTitle('LDAP · pihole-rbac');
	// Nothing saved yet, so LDAP can't be turned on.
	await expect(page.getByRole('checkbox', { name: 'LDAP' })).toBeDisabled();
	await expect(page.getByText('Save the LDAP server settings below first.')).toBeVisible();

	await fillServer(page, state, d.bind_password);
	await expect(page.getByText("ldap:// isn't encrypted")).toBeVisible();
	await page.getByRole('button', { name: 'Save LDAP settings' }).click();
	await expect(page.getByText('LDAP settings saved.')).toBeVisible();
	await expect(page.getByText(/^Stored, changed .* by admin/)).toBeVisible();

	await page.getByRole('checkbox', { name: 'LDAP' }).click();
	await page.getByRole('button', { name: 'Save login methods' }).click();
	await expect(page.getByText('Login methods saved. LDAP login is on.')).toBeVisible();

	// Map the staff group to alice's role, and the check finds the group.
	await page.getByLabel('Group DN').fill(d.staff_group);
	await page.getByLabel('Role').click();
	await page.getByRole('option', { name: 'e2e-one-instance' }).click();
	await page.getByRole('button', { name: 'Add mapping' }).click();
	await expect(page.getByText('Group mapped to e2e-one-instance.')).toBeVisible();
	const row = page.getByRole('listitem').filter({ hasText: d.staff_group });
	await expect(row).toContainText('The group exists, with 2 members.');

	// The test tool says what mark would get, and mark can then log in.
	await page.getByLabel('Username', { exact: true }).fill('mark');
	await page.getByRole('button', { name: 'Look up' }).click();
	const result = page.getByRole('status');
	await expect(result).toContainText('mark would log in with: e2e-one-instance.');
	await expect(result).toContainText('pihole1: clients.view, domains.view, querylog.view');
	expect(await loginWorks(browser, state, { username: 'mark', password: 'mark-ldap-password', about: '' })).toBe(true);

	// On the users page, mark's DN is shortened so it stays in its column, with the full DN in the tooltip; clicking it
	// shows the whole DN.
	await page.goto('/admin/users');
	const dn = page.getByRole('button', { name: /full DN of mark/ });
	await expect(dn).toHaveAttribute('title', d.users.mark);
	await expect(dn).toHaveAttribute('aria-expanded', 'false');
	const roles = page.getByRole('row').filter({ has: dn }).getByRole('cell').nth(2);
	const [dnBox, rolesBox] = [await dn.boundingBox(), await roles.boundingBox()];
	expect(dnBox!.x + dnBox!.width).toBeLessThanOrEqual(rolesBox!.x);
	// The box alone isn't enough: text that doesn't wrap spills out of its box. It must be clipped, with an ellipsis.
	// The DN is longer than the column in any monospace font (Windows' is narrower than Linux's), so it really is clipped:
	// its content is wider than the box.
	await expect(dn).toHaveCSS('overflow-x', 'hidden');
	await expect(dn).toHaveCSS('text-overflow', 'ellipsis');
	const clipped = () => dn.evaluate((el) => el.scrollWidth > el.clientWidth);
	expect(await clipped()).toBe(true);
	await dn.click();
	await expect(dn).toHaveAttribute('aria-expanded', 'true');
	// Opened, all of it shows: nothing is clipped, and it wraps onto more lines.
	await expect.poll(clipped).toBe(false);
	expect((await dn.boundingBox())!.height).toBeGreaterThan(dnBox!.height);
	await page.goto('/admin/ldap');

	// While LDAP is on, settings that don't bind are refused and nothing changes.
	await page.getByLabel('Bind DN').fill('cn=nobody,dc=example,dc=local');
	await page.getByRole('button', { name: 'Save LDAP settings' }).click();
	await expect(page.getByText("The LDAP server couldn't be used, so nothing was saved: it refused the bind DN or password.")).toBeVisible();
	await page.reload();
	await expect(page.getByLabel('Bind DN')).toHaveValue(d.bind_dn);

	// Put things back: remove the mapping, turn LDAP off.
	await row.getByRole('button', { name: /^Remove/ }).click();
	await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
	await expect(page.getByText(/^Mapping removed/)).toBeVisible();
	await page.getByRole('checkbox', { name: 'LDAP' }).click();
	await page.getByRole('button', { name: 'Save login methods' }).click();
	await expect(page.getByText('Login methods saved. LDAP login is off.')).toBeVisible();
	expect(await loginWorks(browser, state, { username: 'mark', password: 'mark-ldap-password', about: '' })).toBe(false);
});

test('a new server address needs the bind password again', async ({ page, state }) => {
	const d = state.seeded.fixture.ldap;
	await openAs(page, state.seeded.fixture.admin, '/admin/ldap');
	// Make sure settings with a password are saved, whatever ran before.
	await apiWrite(page, 'PUT', '/api/v1/settings/ldap', {
		url: d.url, bind_dn: d.bind_dn, base_dn: d.base_dn, user_filter: d.user_filter, bind_password: d.bind_password
	});
	await page.reload();

	await page.getByLabel('Server URL').fill('ldap://127.0.0.1:9');
	await expect(page.getByText("Enter the bind password again: it's only sent to the server it was entered for.")).toBeVisible();
	await page.getByRole('button', { name: 'Save LDAP settings' }).click();
	await expect(page.getByRole('alert')).toContainText('Enter the bind password again');
	await page.reload();
	await expect(page.getByLabel('Server URL')).toHaveValue(d.url);
});

test('roles.manage gets the mappings and the test tool, not the server settings', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.role_lead, '/admin/ldap');
	await expect(page.getByRole('heading', { name: 'Group mappings' })).toBeVisible();
	await expect(page.getByRole('heading', { name: 'Test a user' })).toBeVisible();
	await expect(page.getByRole('heading', { name: 'LDAP server' })).toHaveCount(0);
	await expect(page.getByText('The LDAP server and login methods need the settings.manage permission.')).toBeVisible();
});

test('the LDAP page needs settings.manage or roles.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.user_lead, '/admin/ldap');
	await expect(page.getByText('You need the settings.manage or roles.manage permission')).toBeVisible();
});
