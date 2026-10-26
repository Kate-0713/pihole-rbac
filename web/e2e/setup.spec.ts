// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// First-run setup, against the e2e server whose setup is still open. The tests run in order: the last one completes
// setup, which can't be undone.
import { expect, test } from './fixtures.js';

test.describe.configure({ mode: 'serial' });

const admin = { username: 'firstadmin', password: 'first-admin-password' };

async function fill(page: import('@playwright/test').Page, token: string, password: string, confirm: string) {
	await page.getByLabel('Setup token').fill(token);
	await page.getByLabel('Admin username').fill(admin.username);
	await page.getByLabel('Password', { exact: true }).fill(password);
	await page.getByLabel('Confirm password').fill(confirm);
}

test('every page leads to setup until it is done, with the source link shown', async ({ page }) => {
	for (const path of ['/', '/dashboard', '/login', '/admin/users']) {
		await page.goto(path);
		await expect(page).toHaveURL(/\/setup$/);
	}
	await expect(page.getByText('Set up pihole-rbac')).toBeVisible();
	const source = page.getByRole('link', { name: 'Source code' });
	await expect(source).toHaveAttribute('href', /^https:\/\//);
	await expect(page.getByText('AGPL-3.0-or-later')).toBeVisible();
	await expect(page.getByRole('link', { name: 'Third-party notices' })).toHaveAttribute(
		'href',
		'/THIRD_PARTY_NOTICES.txt'
	);
});

test('the form only submits once the password is typed twice and long enough', async ({ page, state }) => {
	await page.goto('/setup');
	const submit = page.getByRole('button', { name: 'Create admin and log in' });

	await fill(page, state.fresh.setup_token, 'short', 'short');
	await expect(page.getByText('Use at least 12 characters.')).toBeVisible();
	await expect(submit).toBeDisabled();

	await fill(page, state.fresh.setup_token, admin.password, admin.password + 'x');
	await expect(page.getByText("The passwords don't match.")).toBeVisible();
	await expect(submit).toBeDisabled();

	await fill(page, state.fresh.setup_token, admin.password, admin.password);
	await expect(submit).toBeEnabled();
});

test('a wrong setup token is refused, and setup stays open', async ({ page }) => {
	await page.goto('/setup');
	await fill(page, 'not-the-token', admin.password, admin.password);
	await page.getByRole('button', { name: 'Create admin and log in' }).click();
	await expect(page.getByRole('alert')).toBeVisible();
	await expect(page).toHaveURL(/\/setup$/);
});

test('setup creates the admin and logs them in; it never reopens', async ({ page, state }) => {
	await page.goto('/setup');
	await fill(page, state.fresh.setup_token, admin.password, admin.password);
	await page.getByRole('button', { name: 'Create admin and log in' }).click();

	await expect(page).toHaveURL(/\/dashboard/);
	await expect(page.getByRole('button', { name: `Account: ${admin.username}` })).toBeVisible();
	// No instances yet: the admin is pointed at where to add one.
	await expect(page.getByText('No instances yet.')).toBeVisible();

	await page.goto('/setup');
	await expect(page).toHaveURL(/\/dashboard/);
});
