// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The notifications page, against the seeded server and the e2e server's fake Matrix homeserver, which a channel
// reaches over plain HTTP on the loopback. Each test uses a room of its own, so what it reads back is only its own.
import type { APIRequestContext, Page } from '@playwright/test';
import { matrixURL } from './addresses.js';
import { apiWrite, expect, logIn, openAs, test } from './fixtures.js';

async function received(request: APIRequestContext, room: string): Promise<string[]> {
	const res = await request.get(`${matrixURL}?room=${encodeURIComponent(room)}`);
	expect(res.ok()).toBe(true);
	return ((await res.json()) as { body: string }[]).map((m) => m.body);
}

// nthReceived waits until the room has n messages and returns the newest.
async function nthReceived(request: APIRequestContext, room: string, n: number): Promise<string> {
	await expect.poll(async () => (await received(request, room)).length, { timeout: 10_000 }).toBeGreaterThanOrEqual(n);
	return (await received(request, room))[n - 1];
}

const item = (page: Page, name: string) => page.locator(`li[data-channel="${name}"]`);

async function menu(page: Page, name: string, action: string) {
	await page.getByRole('button', { name: `Actions for ${name}` }).click();
	await page.getByRole('menuitem', { name: action }).click();
}

test('a Matrix channel: add, test, notify, change, disable and delete', async ({ page, browser, request, state }) => {
	const { homeserver, token } = state.seeded.fixture.matrix;
	const room = `!e2e-${Date.now()}:localhost`;
	const name = `Room ${Date.now()}`;

	await openAs(page, state.seeded.fixture.admin, '/');
	await page.getByRole('button', { name: 'Admin', exact: true }).click();
	await page.getByRole('menuitem', { name: 'Notifications' }).click();
	await expect(page).toHaveURL('/admin/notifications');
	await expect(page).toHaveTitle('Notifications · pihole-rbac');

	// Add it. Plain HTTP is refused until it is allowed.
	await page.getByRole('button', { name: 'Add a channel' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Kind', { exact: true }).click();
	await page.getByRole('option', { name: 'Matrix' }).click();
	await dialog.getByLabel('Name', { exact: true }).fill(name);
	await dialog.getByLabel('Homeserver', { exact: true }).fill(homeserver);
	await dialog.getByLabel('Room ID', { exact: true }).fill(room);
	await dialog.getByLabel('Access token', { exact: true }).fill(token);
	await dialog.getByLabel('login', { exact: true }).check();
	await expect(dialog.getByText('Use https://, or allow plain HTTP below.')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	await dialog.getByLabel('Allow plain HTTP', { exact: true }).check();
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText(`${name} added.`)).toBeVisible();
	const row = item(page, name);
	await expect(row).toContainText(`${room} on ${homeserver}`);
	await expect(row).toContainText(/Stored, changed .* by admin/);
	await expect(row).toContainText('login');

	// Send test reaches the room.
	await menu(page, name, 'Send test');
	await expect(page.getByText(`${name}: test message sent.`)).toBeVisible();
	expect(await nthReceived(request, room, 1)).toContain(`Test message from pihole-rbac for channel ${name}`);

	// A login is an event it receives.
	const other = await browser.newContext({ baseURL: state.seeded.url });
	const bob = await other.newPage();
	await bob.goto('/login');
	await logIn(bob, state.seeded.fixture.no_instances);
	await expect(bob).not.toHaveURL(/\/login/);
	await other.close();
	expect(await nthReceived(request, room, 2)).toMatch(/^bob login — succeeded$/);

	// Another homeserver address needs the token again; the old destination is told.
	await menu(page, name, 'Edit');
	await dialog.getByLabel('Homeserver', { exact: true }).fill(homeserver.replace('127.0.0.1', 'localhost'));
	await expect(dialog.getByText('Enter the access token again to use the new homeserver settings')).toBeVisible();
	await expect(dialog.getByText('Saving tells the channel\'s current destination that it now sends somewhere else')).toBeVisible();
	await expect(dialog.getByText('Paste the access token.')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled();
	await dialog.getByLabel('Access token', { exact: true }).fill(token);
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText(`${name} saved.`).last()).toBeVisible();
	expect(await nthReceived(request, room, 3)).toContain('was changed by admin: its destination or secret changed');

	// Taking an event away warns too.
	await menu(page, name, 'Edit');
	await dialog.getByLabel('logout', { exact: true }).check();
	await dialog.getByLabel('login', { exact: true }).uncheck();
	await expect(dialog.getByText('it no longer receives login')).toBeVisible();
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText(`${name} saved.`).last()).toBeVisible();
	expect(await nthReceived(request, room, 4)).toContain('it no longer receives login');
	await expect(row).toContainText('logout');

	// A wrong token: the test says how the homeserver refused it, and the old token's destination is told.
	await menu(page, name, 'Replace access token');
	await page.getByLabel('New access token', { exact: true }).fill('syt_wrong_token');
	await page.getByRole('button', { name: 'Store access token' }).click();
	await expect(page.getByText(`New access token stored for ${name}.`).last()).toBeVisible();
	expect(await nthReceived(request, room, 5)).toContain('access token was replaced');
	await menu(page, name, 'Send test');
	await expect(page.getByText(`${name}: the test message wasn't accepted: refused with status 401 (M_UNKNOWN_TOKEN)`)).toBeVisible();
	await menu(page, name, 'Replace access token');
	await page.getByLabel('New access token', { exact: true }).fill(token);
	await page.getByRole('button', { name: 'Store access token' }).click();
	await expect(page.getByText(`New access token stored for ${name}.`).last()).toBeVisible();

	// Disabled: told once, with a last message. Enabled again, then deleted after a confirmation.
	await menu(page, name, 'Disable');
	await expect(page.getByRole('alertdialog')).toContainText('It gets one last message saying so.');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Disable' }).click();
	await expect(page.getByText(`${name} disabled.`)).toBeVisible();
	await expect(row).toContainText('Disabled');
	expect(await nthReceived(request, room, 6)).toContain('it was disabled');
	await menu(page, name, 'Enable');
	await expect(page.getByText(`${name} enabled.`)).toBeVisible();
	await menu(page, name, 'Delete');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(page.getByText(`${name} deleted.`)).toBeVisible();
	await expect(row).toHaveCount(0);
	expect(await nthReceived(request, room, 7)).toContain('it was deleted');
});

test('a Discord channel only takes a Discord webhook URL', async ({ page, state }) => {
	const name = `Discord ${Date.now()}`;
	await openAs(page, state.seeded.fixture.admin, '/admin/notifications');
	await page.getByRole('button', { name: 'Add a channel' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill(name);
	await dialog.getByLabel('Webhook URL', { exact: true }).fill('https://192.168.1.10/api/webhooks/1/token');
	await dialog.getByLabel('Enabled', { exact: true }).uncheck(); // so nothing is ever sent to Discord from the tests
	await expect(dialog.getByText('Use a Discord webhook URL')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	await dialog.getByLabel('Webhook URL', { exact: true }).fill('https://discord.com/api/webhooks/123456/e2e-token');
	// A whole group at once.
	await dialog.getByLabel('Pi-hole changes', { exact: true }).check();
	await expect(dialog.getByLabel('domain_add', { exact: true })).toBeChecked();
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText(`${name} added.`)).toBeVisible();
	const row = item(page, name);
	await expect(row).toContainText('Webhook 123456');
	await expect(row).toContainText('Disabled');
	await expect(row).not.toContainText('e2e-token');

	// A disabled channel is deleted without a last message.
	await menu(page, name, 'Delete');
	await expect(page.getByRole('alertdialog')).not.toContainText('last message');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(row).toHaveCount(0);
});

test('protected groups: an alert when a client joins one, and a warning when it stops', async ({ page, request, state }) => {
	const { homeserver, token } = state.seeded.fixture.matrix;
	const pihole1 = state.seeded.fixture.instances[0];
	const room = `!protected-${Date.now()}:localhost`;
	const name = `Protected ${Date.now()}`;
	await openAs(page, state.seeded.fixture.admin, '/admin/notifications');
	const created = await apiWrite(page, 'POST', '/api/v1/notifications/channels', {
		kind: 'matrix', name, enabled: true, events: ['protected_group_add'], secret: token,
		matrix: { homeserver, room_id: room, allow_http: true }
	});
	const channel = (await created.json()) as { id: number };
	await page.reload();
	const card = page.locator('[data-slot="card"]').filter({ hasText: 'Protected groups' });
	await expect(card).toContainText(`Alerts go to ${name}`);

	// Protect kids on pihole1.
	await card.getByRole('button', { name: 'Edit' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Instance or group').first().click();
	await page.getByRole('option', { name: pihole1.name }).click();
	await dialog.getByLabel('Pi-hole groups, separated by commas').first().fill('kids');
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('Protected groups saved.')).toBeVisible();
	await expect(card.getByRole('list', { name: 'Protected groups' })).toContainText(new RegExp(`${pihole1.name}\\s*instance\\s*kids`));

	// The lab subnet joins kids: an alert.
	const target = `i-${pihole1.id}`;
	const { groups } = await (await page.request.get(`/api/v1/targets/${target}/groups`)).json();
	const kids = groups.find((g: { name: string }) => g.name === 'kids').id;
	await apiWrite(page, 'PATCH', `/api/v1/targets/${target}/clients`, { client: '10.0.0.0/24', groups: [0, kids] });
	try {
		expect(await nthReceived(request, room, 1)).toBe(`🚨 admin added client 10.0.0.0/24 to protected group kids on ${pihole1.name}`);

		// Taking it away warns the channel first.
		await card.getByRole('button', { name: 'Edit' }).click();
		await dialog.getByRole('button', { name: 'Remove row 1' }).click();
		await expect(dialog.getByText(`these alerts stop: kids on ${pihole1.name}`)).toBeVisible();
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('Protected groups saved.').last()).toBeVisible();
		await expect(card).toContainText('None yet.');
		expect(await nthReceived(request, room, 2)).toContain(`no more alerts when a client is added to kids on ${pihole1.name}`);
	} finally {
		// Put the client back for the other tests, and remove the channel.
		await apiWrite(page, 'PATCH', `/api/v1/targets/${target}/clients`, { client: '10.0.0.0/24', groups: [0] });
		await apiWrite(page, 'DELETE', `/api/v1/notifications/channels/${channel.id}`);
	}
});

test('the notifications page needs notifications.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.no_instances, '/admin/notifications');
	await expect(page.getByText('You need the notifications.manage permission')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Add a channel' })).toHaveCount(0);
});
