// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The app shell: the nav built from permissions, the target picker and the target kept in the URL. Against the
// seeded server, as three users: the admin, a user with one instance, and a user with none.
import { expect, openAs, picker, test } from './fixtures.js';

const mainNav = (page: import('@playwright/test').Page) => page.getByRole('navigation', { name: 'Main' });

test('the admin sees every page and the Admin menu', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/');
	const nav = mainNav(page);
	for (const name of ['Dashboard', 'Domains', 'Clients', 'Query log']) {
		await expect(nav.getByRole('link', { name })).toHaveAttribute('href', /\?target=i-1$/);
	}
	await expect(nav.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('aria-current', 'page');

	await nav.getByRole('button', { name: 'Admin' }).click();
	for (const name of ['Instances', 'Groups', 'Users', 'Roles', 'Sessions', 'Audit log', 'Client reset', 'System']) {
		await expect(page.getByRole('menuitem', { name })).toBeVisible();
	}
});

test('a user with one instance sees only what they may do there', async ({ page, state }) => {
	const { one_instance } = state.seeded.fixture;
	await openAs(page, one_instance, '/');
	await expect(page).toHaveURL('/dashboard?target=i-1');

	const nav = mainNav(page);
	await expect(nav.getByRole('link', { name: 'Domains' })).toBeVisible();
	await expect(nav.getByRole('link', { name: 'Query log' })).toBeVisible();
	await expect(nav.getByRole('button', { name: 'Admin' })).toHaveCount(0);

	await picker(page).click();
	await expect(page.getByRole('option')).toHaveText([/pihole1$/]);
});

test("an instance the user can't use in the URL is swapped for one they can, saying so", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-2');
	await expect(page).toHaveURL('/dashboard?target=i-1');
	await expect(page.getByText("That instance isn't available to you. Showing pihole1 instead.")).toBeVisible();
});

test('a user with no instances sees no instance pages and no picker', async ({ page, state }) => {
	const { no_instances } = state.seeded.fixture;
	await openAs(page, no_instances, '/');
	await expect(page).toHaveURL('/dashboard');
	await expect(page.getByText("You don't have access to any instance yet.")).toBeVisible();
	await expect(page.getByText('No instances available')).toBeVisible();
	await expect(mainNav(page).getByRole('link', { name: 'Domains' })).toHaveCount(0);

	// audit.view is their only permission, so the Admin menu has the audit log and nothing else.
	await mainNav(page).getByRole('button', { name: 'Admin' }).click();
	await expect(page.getByRole('menuitem')).toHaveText(['Audit log']);
});

test('picking an instance changes the URL, keeps the page, and is remembered', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await picker(page).click();
	await expect(page.getByRole('option')).toHaveText([/pihole1$/, /pihole2$/, /pihole3$/]);
	await page.getByRole('option', { name: /pihole2$/ }).click();
	await expect(page).toHaveURL('/dashboard?target=i-2');
	await expect(page.getByRole('main').getByText('pihole2')).toBeVisible();
	await expect(mainNav(page).getByRole('link', { name: 'Domains' })).toHaveAttribute('href', '/domains?target=i-2');

	// A link without a target opens the one picked last in this browser.
	await page.goto('/dashboard');
	await expect(page).toHaveURL('/dashboard?target=i-2');
});

test('the picker shows each instance health, and an instance that is down says so', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-3');
	// pihole3 points at a port nothing listens on; the server's first probe finds it down, and the others up. The
	// state is a dot with a text label for screen readers, which is part of each option's name.
	await expect(page.getByRole('main').getByText('· down')).toBeVisible();
	await picker(page).click();
	await expect(page.getByRole('option')).toHaveText(['Up pihole1', 'Up pihole2', 'Down pihole3'].map((t) => new RegExp(t)));
});

test('admin page URLs never carry a target, and the picker is hidden there', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/instances?target=i-2');
	await expect(page).toHaveURL('/admin/instances');
	await expect(picker(page)).toHaveCount(0);
});

test('unknown pages show the not-found page', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/');
	await page.goto('/no-such-page');
	await expect(page.getByRole('heading', { name: "This page doesn't exist" })).toBeVisible();
	await expect(page).toHaveTitle('Not found · pihole-rbac');
});

test('the header fits a phone screen without sideways scrolling', async ({ page, state }) => {
	await page.setViewportSize({ width: 375, height: 812 });
	await openAs(page, state.seeded.fixture.admin, '/');
	await expect(picker(page)).toBeVisible();
	const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
	expect(overflow).toBeLessThanOrEqual(0);
});
