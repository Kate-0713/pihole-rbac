// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The log forwarding page, against the seeded server. A collector is a TCP server started by the test on the
// loopback, which the app connects to and which keeps what it receives. Each test names its destinations itself, so
// what it reads back is only its own.
import net from 'node:net';
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

type Collector = { port: number; text: () => string; close: () => Promise<void> };

async function collector(): Promise<Collector> {
	const chunks: string[] = [];
	const sockets = new Set<net.Socket>();
	const server = net.createServer((s) => {
		sockets.add(s);
		s.on('data', (d) => chunks.push(d.toString('utf8')));
		s.on('error', () => {});
		s.on('close', () => sockets.delete(s));
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const port = (server.address() as net.AddressInfo).port;
	return {
		port,
		text: () => chunks.join(''),
		close: () =>
			new Promise<void>((resolve) => {
				for (const s of sockets) s.destroy();
				server.close(() => resolve());
			})
	};
}

// messages counts the syslog messages of an action: its name is the MSGID, which follows the header's fixed fields.
const messages = (c: Collector, action: string) => (c.text().match(new RegExp(` ${action} - `, 'g')) ?? []).length;

const item = (page: Page, name: string) => page.locator(`li[data-destination="${name}"]`);

async function menu(page: Page, name: string, action: string) {
	await page.getByRole('button', { name: `Actions for ${name}` }).click();
	await page.getByRole('menuitem', { name: action }).click();
}

test('a destination: add, test, move, rename, disable and delete, telling the place it sent to', async ({ page, state }) => {
	const first = await collector();
	const second = await collector();
	const name = `Collector ${Date.now()}`;
	try {
		await openAs(page, state.seeded.fixture.admin, '/');
		await page.getByRole('button', { name: 'Admin', exact: true }).click();
		await page.getByRole('menuitem', { name: 'Log forwarding' }).click();
		await expect(page).toHaveURL('/admin/log-forwarding');
		await expect(page).toHaveTitle('Log forwarding · pihole-rbac');

		// Add it over TCP, which has to be agreed to.
		await page.getByRole('button', { name: 'Add a destination' }).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog.getByLabel('Port', { exact: true })).toHaveValue('6514');
		await dialog.getByLabel('Name', { exact: true }).fill(name);
		await dialog.getByLabel('Host', { exact: true }).fill('127.0.0.1');
		await dialog.getByLabel('Transport', { exact: true }).click();
		await page.getByRole('option', { name: 'TCP, unencrypted' }).click();
		await expect(dialog.getByLabel('Port', { exact: true })).toHaveValue('514');
		await dialog.getByLabel('Port', { exact: true }).fill(String(first.port));
		await expect(dialog.getByText('sends the audit log unencrypted')).toBeVisible();
		await expect(dialog.getByText('Tick the box to send the log unencrypted.')).toBeVisible();
		await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
		await dialog.getByLabel('Send the log unencrypted', { exact: true }).check();
		await dialog.getByRole('button', { name: 'Add' }).click();
		await expect(page.getByText(`${name} added.`)).toBeVisible();
		const row = item(page, name);
		await expect(row).toContainText('TCP, unencrypted');
		await expect(row).toContainText(`127.0.0.1:${first.port}`);

		// It starts at the newest entry, so its own creation is the first thing it receives.
		await expect.poll(() => messages(first, 'logdest_create')).toBe(1);
		await expect(row).toContainText('Working');
		await expect(row).toContainText(/Last sent /);

		// Send test reaches the collector, and isn't an entry in the log.
		await menu(page, name, 'Send test');
		await expect(page.getByText(`${name}: Sent.`)).toBeVisible();
		await expect.poll(() => messages(first, 'test')).toBe(1);

		// A new port is a move: the old place is told, and the new one starts at the change. Staying on TCP needs no
		// agreement again.
		await menu(page, name, 'Edit');
		await expect(dialog.getByLabel('Send the log unencrypted', { exact: true })).toHaveCount(0);
		await dialog.getByLabel('Port', { exact: true }).fill(String(second.port));
		await expect(dialog.getByText('the log now goes somewhere else')).toBeVisible();
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText(`${name} saved.`).last()).toBeVisible();
		await expect.poll(() => messages(first, 'logdest_update')).toBe(1);
		expect(first.text()).toContain(`"to":${second.port}`);

		// A rename isn't a move: nothing is told to the old place, and the new one gets the entry.
		await menu(page, name, 'Edit');
		await expect(dialog.getByText('Saving tells the place it sends to')).toHaveCount(0);
		await dialog.getByLabel('Name', { exact: true }).fill(`${name} renamed`);
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText(`${name} renamed saved.`).last()).toBeVisible();
		await expect.poll(() => messages(second, 'logdest_update')).toBe(1);
		expect(messages(first, 'logdest_update')).toBe(1);
		expect(messages(second, 'logdest_create')).toBe(0);
		const renamed = `${name} renamed`;

		// Disabled: asked first, and the collector is told. Enabled again, then deleted.
		await menu(page, renamed, 'Disable');
		await expect(page.getByRole('alertdialog')).toContainText('first sent what it hadn’t had');
		await page.getByRole('alertdialog').getByRole('button', { name: 'Disable' }).click();
		await expect(page.getByText(`${renamed} disabled.`)).toBeVisible();
		await expect(item(page, renamed)).toContainText('Disabled');
		await expect.poll(() => messages(second, 'logdest_update')).toBe(2);
		await menu(page, renamed, 'Enable');
		await expect(page.getByText(`${renamed} enabled.`)).toBeVisible();
		await expect(item(page, renamed)).toContainText(/Working|Idle/);
		await menu(page, renamed, 'Delete');
		await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
		await expect(page.getByText(`${renamed} deleted.`)).toBeVisible();
		await expect(item(page, renamed)).toHaveCount(0);
		await expect.poll(() => messages(second, 'logdest_delete')).toBe(1);
	} finally {
		await first.close();
		await second.close();
	}
});

test('the form refuses what the server would, and a test says why it failed', async ({ page, state }) => {
	const name = `Unreachable ${Date.now()}`;
	await openAs(page, state.seeded.fixture.admin, '/admin/log-forwarding');
	await page.getByRole('button', { name: 'Add a destination' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name', { exact: true }).fill(name);
	await dialog.getByLabel('Host', { exact: true }).fill('https://logs.lan');
	await expect(dialog.getByText('Use a host name or an address, with no scheme, port or spaces.')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	await dialog.getByLabel('Host', { exact: true }).fill('127.0.0.1');
	await dialog.getByLabel('Port', { exact: true }).fill('70000');
	await expect(dialog.getByText('The port is a number from 1 to 65535.')).toBeVisible();
	await dialog.getByLabel('Port', { exact: true }).fill('1'); // nothing listens there
	await dialog.getByLabel('Enabled', { exact: true }).uncheck(); // so no forwarder retries it
	await dialog.getByLabel('CA file (optional)', { exact: true }).fill('ca.pem');
	await expect(dialog.getByText('Use an absolute path to a PEM file.')).toBeVisible();
	await dialog.getByLabel('CA file (optional)', { exact: true }).fill('');
	await dialog.getByLabel('Don’t check the collector’s certificate', { exact: true }).check();
	await expect(dialog.getByLabel('CA file (optional)', { exact: true })).toHaveCount(0);
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(page.getByText(`${name} added.`)).toBeVisible();
	const row = item(page, name);
	await expect(row).toContainText('Disabled');
	await expect(row).toContainText('Certificate not checked');

	await menu(page, name, 'Send test');
	await expect(page.getByText(`${name}: the test message wasn't sent: Couldn't connect.`)).toBeVisible();

	await menu(page, name, 'Delete');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(row).toHaveCount(0);
});

test('a destination that is down shows as failing, with what is waiting for it', async ({ page, state }) => {
	const c = await collector();
	const name = `Flaky ${Date.now()}`;
	const renamed = `${name} b`;
	await openAs(page, state.seeded.fixture.admin, '/admin/log-forwarding');
	try {
		await page.getByRole('button', { name: 'Add a destination' }).click();
		const dialog = page.getByRole('dialog');
		await dialog.getByLabel('Name', { exact: true }).fill(name);
		await dialog.getByLabel('Host', { exact: true }).fill('127.0.0.1');
		await dialog.getByLabel('Transport', { exact: true }).click();
		await page.getByRole('option', { name: 'TCP, unencrypted' }).click();
		await dialog.getByLabel('Port', { exact: true }).fill(String(c.port));
		await dialog.getByLabel('Send the log unencrypted', { exact: true }).check();
		await dialog.getByRole('button', { name: 'Add' }).click();
		await expect(page.getByText(`${name} added.`)).toBeVisible();
		await expect.poll(() => messages(c, 'logdest_create')).toBe(1);
	} finally {
		await c.close();
	}
	// The collector is gone. A change makes an entry it can't be sent, and the page shows it failing.
	await menu(page, name, 'Edit');
	await page.getByRole('dialog').getByLabel('Name', { exact: true }).fill(renamed);
	await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText(`${renamed} saved.`).last()).toBeVisible();
	await expect(async () => {
		await page.reload();
		await expect(item(page, renamed)).toContainText('Failing since', { timeout: 1_000 });
	}).toPass({ timeout: 20_000 });
	await expect(item(page, renamed)).toContainText('couldn’t connect');
	await expect(item(page, renamed)).toContainText(/entr(y|ies) still to send/);

	await menu(page, renamed, 'Delete');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
	await expect(item(page, renamed)).toHaveCount(0);
});

test('the log forwarding page needs logging.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.no_instances, '/admin/log-forwarding');
	await expect(page.getByText('You need the logging.manage permission')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Add a destination' })).toHaveCount(0);
});
