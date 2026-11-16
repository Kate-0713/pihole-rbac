// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The DHCP page, against the seeded server. pihole1's fake Pi-hole starts with DHCP off and a range set, two static
// leases (nas, and tv with a lease time, which the app only lets you replace), and three leases, with app_sudo on.
// pihole2 has DHCP on, so turning it on for pihole1 warns. Tests that change something put it back.
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

const leases = (page: Page) => page.getByRole('table', { name: 'Leases' });
const statics = (page: Page) => page.getByRole('table', { name: 'Static leases' });

test('lists the leases and static leases', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'DHCP' }).click();
	await expect(page).toHaveURL('/dhcp?target=i-1');
	await expect(page).toHaveTitle('pihole1 · DHCP · pihole-rbac');

	// DHCP is off, so the leases are the lease file's, and the page says they may be old.
	await expect(page.getByText(/DHCP is off on pihole1/)).toBeVisible();
	await expect(page.getByRole('tab', { name: 'Leases (3)' })).toBeVisible();
	await expect(leases(page)).toContainText('192.168.1.120');
	await expect(leases(page)).toContainText('phone');
	// A lease that is static already offers no "Make static".
	await expect(page.getByRole('button', { name: 'Make 192.168.1.10 static' })).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Make 192.168.1.120 static' })).toBeVisible();

	await page.getByRole('tab', { name: 'Static leases (2)' }).click();
	await expect(statics(page)).toContainText('aa:bb:cc:00:00:01');
	await expect(statics(page)).toContainText('192.168.1.11');
	// One added outside the app, with a lease time, can only be replaced.
	await expect(page.getByRole('button', { name: /^Replace aa:bb:cc:00:00:02/ })).toBeVisible();
	await expect(page.getByRole('button', { name: /^Change aa:bb:cc:00:00:01/ })).toBeVisible();
});

test("a user without dhcp.view doesn't see the page", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await expect(page.getByRole('link', { name: 'DHCP' })).toHaveCount(0);
	await page.goto('/dhcp?target=i-1');
	await expect(page.getByText("You can't view the DHCP of pihole1.")).toBeVisible();
});

test('making a lease static, then deleting the static lease', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dhcp?target=i-1');
	await page.getByRole('button', { name: 'Make 192.168.1.120 static' }).click();
	const dialog = page.getByRole('dialog');
	// The form starts from the lease.
	await expect(dialog.getByLabel('Hardware address')).toHaveValue('aa:bb:cc:00:00:09');
	await expect(dialog.getByLabel('Address', { exact: true })).toHaveValue('192.168.1.120');
	await expect(dialog.getByLabel('Name (optional)')).toHaveValue('phone');
	await dialog.getByLabel('Address', { exact: true }).fill('192.168.2.5');
	await expect(dialog.getByText("The address isn't in the DHCP subnet", { exact: false })).toBeVisible();
	await dialog.getByLabel('Address', { exact: true }).fill('192.168.1.120');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText(/192\.168\.1\.120.*added on pihole1/)).toBeVisible();

	await page.getByRole('tab', { name: /^Static leases/ }).click();
	await expect(statics(page)).toContainText('aa:bb:cc:00:00:09');
	await page.getByRole('button', { name: 'Delete aa:bb:cc:00:00:09' }).click();
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText(/deleted on pihole1/)).toBeVisible();
	await expect(statics(page)).not.toContainText('aa:bb:cc:00:00:09');
});

test('turning DHCP on asks first, and warns about the other server', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dhcp?target=i-1');
	await page.getByRole('tab', { name: 'Settings' }).click();
	const form = page.getByRole('form', { name: 'DHCP settings' });
	await form.getByLabel('DHCP server on').check();
	await form.getByRole('button', { name: 'Save' }).click();

	const confirm = page.getByRole('alertdialog');
	await expect(confirm.getByText('Restart DNS and DHCP on pihole1?')).toBeVisible();
	await expect(confirm.getByText(/DHCP is already on for pihole2/)).toBeVisible();
	await confirm.getByRole('button', { name: 'Save and restart' }).click();
	await expect(page.getByText('DHCP settings saved on pihole1.')).toBeVisible();
	// With DHCP on, the "may be old" banner goes.
	await expect(page.getByText(/DHCP is off on pihole1/)).toHaveCount(0);

	// Put it back.
	await form.getByLabel('DHCP server on').uncheck();
	await form.getByRole('button', { name: 'Save' }).click();
	await confirm.getByRole('button', { name: 'Save and restart' }).click();
	await expect(page.getByText(/DHCP is off on pihole1/)).toBeVisible();
});

test('a change that needs no confirmation saves straight away, and bad input is caught', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dhcp?target=i-1');
	await page.getByRole('tab', { name: 'Settings' }).click();
	const form = page.getByRole('form', { name: 'DHCP settings' });
	await form.getByLabel('Lease time').fill('1x');
	await expect(form.getByRole('button', { name: 'Save' })).toBeDisabled();
	await form.getByLabel('Lease time').fill('12h');
	await form.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('DHCP settings saved on pihole1.')).toBeVisible();
	await expect(page.getByRole('alertdialog')).toHaveCount(0);

	await form.getByLabel('Lease time').fill('24h');
	await form.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('DHCP settings saved on pihole1.').last()).toBeVisible();
});
