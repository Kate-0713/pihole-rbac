// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Your sessions, everyone's sessions, and the session settings, against the seeded server. The sessions tests use a
// user of their own, gina, so the counts don't depend on other tests; the settings test puts the defaults back.
import type { Browser, BrowserContext, Page } from '@playwright/test';
import { apiWrite, expect, logIn, openAs, test, type State, type User } from './fixtures.js';

const gina: User = { username: 'gina', password: 'gina-password-12', about: '' };

// A logged-in browser of its own.
async function browserAs(browser: Browser, state: State, user: User): Promise<{ context: BrowserContext; page: Page }> {
	const context = await browser.newContext({ baseURL: state.seeded.url });
	const page = await context.newPage();
	await page.goto('/login');
	await logIn(page, user);
	await expect(page).not.toHaveURL(/\/login/);
	return { context, page };
}

async function withGina(browser: Browser, state: State, fn: () => Promise<void>) {
	const admin = await browserAs(browser, state, state.seeded.fixture.admin);
	const { roles } = await (await admin.page.request.get('/api/v1/roles')).json();
	const reader = roles.find((r: { name: string }) => r.name === 'reader').id;
	const res = await apiWrite(admin.page, 'POST', '/api/v1/users', { username: gina.username, password: gina.password, role_ids: [reader] });
	const { id } = await res.json();
	try {
		await fn();
	} finally {
		await apiWrite(admin.page, 'DELETE', `/api/v1/users/${id}`);
		await admin.context.close();
	}
}

const items = (page: Page) => page.getByRole('listitem');

test('your sessions: see where you are logged in, end another, then log out', async ({ browser, state }) => {
	await withGina(browser, state, async () => {
		const laptop = await browserAs(browser, state, gina);
		const phone = await browserAs(browser, state, gina);

		await laptop.page.getByRole('button', { name: 'Account: gina' }).click();
		await laptop.page.getByRole('menuitem', { name: 'Your sessions' }).click();
		await expect(laptop.page).toHaveURL('/account/sessions');
		await expect(laptop.page).toHaveTitle('Your sessions · pihole-rbac');
		// Account pages don't act on an instance, so there's no picker.
		await expect(laptop.page.getByRole('combobox', { name: 'Instance' })).toHaveCount(0);
		await expect(items(laptop.page)).toHaveCount(2);
		await expect(items(laptop.page).filter({ hasText: 'This session' })).toHaveCount(1);

		// Ending your other session needs no confirmation, and that browser is logged out.
		await items(laptop.page).filter({ hasNotText: 'This session' }).getByRole('button', { name: /^End/ }).click();
		await expect(laptop.page.getByText('Session ended.')).toBeVisible();
		await expect(items(laptop.page)).toHaveCount(1);
		await phone.page.reload();
		await expect(phone.page).toHaveURL(/\/login/);

		// Logging this one out asks first.
		await items(laptop.page).getByRole('button', { name: 'End this session' }).click();
		await laptop.page.getByRole('alertdialog').getByRole('button', { name: 'Log out' }).click();
		await expect(laptop.page).toHaveURL(/\/login/);
		await laptop.context.close();
		await phone.context.close();
	});
});

test("with sessions.manage, everyone's sessions, and ending one", async ({ page, browser, state }) => {
	await withGina(browser, state, async () => {
		const elsewhere = await browserAs(browser, state, gina);
		await openAs(page, state.seeded.fixture.admin, '/admin/sessions');
		await expect(page).toHaveTitle('Sessions · pihole-rbac');
		const ginas = items(page).filter({ hasText: /^gina ·/ });
		await expect(ginas).toHaveCount(1);
		await ginas.getByRole('button', { name: /^End gina's session/ }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm).toContainText("End gina's session?");
		await confirm.getByRole('button', { name: 'End session' }).click();
		await expect(page.getByText("gina's session ended.")).toBeVisible();
		await expect(ginas).toHaveCount(0);
		await elsewhere.page.reload();
		await expect(elsewhere.page).toHaveURL(/\/login/);
		await elsewhere.context.close();
	});
});

test('without sessions.manage the admin sessions page points to your own', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/admin/sessions');
	await expect(page.getByText("You need the sessions.manage permission to see everyone's sessions.")).toBeVisible();
	await page.getByRole('link', { name: 'Your sessions' }).click();
	await expect(page).toHaveURL('/account/sessions');
	await expect(items(page).filter({ hasText: 'This session' })).toHaveCount(1);
});

test('the session settings', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/settings');
	await expect(page).toHaveTitle('Settings · pihole-rbac');
	const lifetime = page.getByLabel('Session lifetime (minutes)');
	const idle = page.getByLabel('Idle timeout (minutes)');
	await expect(lifetime).toHaveValue('480');
	await expect(page.getByText('8 hours from login.')).toBeVisible();

	// The rules show as you type, and the button waits for them.
	await idle.fill('600');
	await expect(page.getByText("The idle timeout can't be longer than the session lifetime.")).toBeVisible();
	await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled();

	await lifetime.fill('720');
	await idle.fill('45');
	await expect(page.getByText('12 hours from login.')).toBeVisible();
	await page.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('Session settings saved.')).toBeVisible();
	await page.reload();
	await expect(idle).toHaveValue('45');
	await expect(page.getByText(/^Last saved .* by admin\.$/)).toBeVisible();

	// Put the defaults back for the other tests.
	await lifetime.fill('480');
	await idle.fill('60');
	await page.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('Session settings saved.')).toBeVisible();
});

test('the settings page needs settings.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.no_instances, '/admin/settings');
	await expect(page.getByText('You need the settings.manage permission')).toBeVisible();
});
