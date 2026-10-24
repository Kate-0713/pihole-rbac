// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Logging in and out, and where the app sends people, against the seeded e2e server.
import { expect, logIn, openAs, test } from './fixtures.js';

test('without a session every app page leads to login, which returns there afterwards', async ({ page, state }) => {
	const { admin } = state.seeded.fixture;
	await page.goto('/dashboard?target=i-2');
	await expect(page).toHaveURL('/login?next=%2Fdashboard%3Ftarget%3Di-2');
	await expect(page).toHaveTitle('Log in · pihole-rbac');

	await logIn(page, admin);
	await expect(page).toHaveURL('/dashboard?target=i-2');
});

test('/ opens the dashboard of the first instance', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/');
	await expect(page).toHaveURL('/dashboard?target=i-1');
	await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

test('a wrong password is refused with the same message as an unknown user', async ({ page, state }) => {
	const { admin } = state.seeded.fixture;
	await page.goto('/login');
	await logIn(page, { ...admin, password: 'not-the-password' });
	const wrongPassword = await page.getByRole('alert').textContent();
	await expect(page).toHaveURL('/login');

	await logIn(page, { ...admin, username: 'nobody-here' });
	await expect(page.getByRole('alert')).toHaveText(wrongPassword ?? '');
});

test('a next= that leaves the site is ignored', async ({ page, state }) => {
	for (const next of ['https://evil.example/', '//evil.example/x']) {
		await page.context().clearCookies();
		await page.goto(`/login?next=${encodeURIComponent(next)}`);
		await logIn(page, state.seeded.fixture.admin);
		await expect(page).toHaveURL('/dashboard?target=i-1');
	}
});

test('a logged-in visitor is sent away from the login page', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/');
	await page.goto('/login?next=%2Fdashboard%3Ftarget%3Di-2');
	await expect(page).toHaveURL('/dashboard?target=i-2');
});

test('logging out ends the session on the server too', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/');
	await page.getByRole('button', { name: 'Account: admin' }).click();
	await page.getByRole('menuitem', { name: 'Log out' }).click();
	await expect(page).toHaveURL('/login');

	await page.goto('/dashboard?target=i-1');
	await expect(page).toHaveURL(/\/login\?next=/);
	const res = await page.request.get('/api/v1/auth/session');
	expect(res.status()).toBe(401);
});

test('a session that ends while the app is open sends the user to log in', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/');
	await expect(page).toHaveURL('/dashboard?target=i-1');
	// Drop the session cookie, as an expiry or a revocation would, then use the app.
	await page.context().clearCookies();
	await page.getByRole('combobox', { name: 'Instance' }).click();
	await expect(page).toHaveURL(/\/login\?next=%2Fdashboard/);
});
