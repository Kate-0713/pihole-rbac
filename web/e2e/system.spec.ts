// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The System page and the update banner. The version, the secrets and reloading them run against the seeded server,
// whose update check is off (the e2e server sets PIHOLE_RBAC_UPDATE_CHECK=false, so no test reaches GitHub). An
// update or a restart would take the shared server away, so those tests answer the update and restart endpoints
// in the browser with page.route; the Go tests cover the endpoints themselves.
import type { Page, Route } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

type Request = {
	id: number;
	requested_at: string;
	requested_by: string;
	status: 'pending' | 'running' | 'done' | 'failed' | 'rolled_back';
	log: string;
	target_version?: string;
	finished_at?: string;
};

function updateStatus(over: Record<string, unknown> = {}) {
	return {
		current_version: '2.0.0',
		development: false,
		install: 'lxc',
		check_enabled: true,
		checked_at: '2026-10-26T09:00:00Z',
		latest: { version: 'v2.1.0', url: 'https://github.com/Kate-0713/pihole-rbac/releases/tag/v2.1.0' },
		update_available: true,
		can_request: true,
		requests: [] as Request[],
		...over
	};
}

// A fake updater behind GET and POST /api/v1/system/update: a request is pending, then running, then done, one step
// per status read, and the server then reports the new version.
async function fakeUpdater(page: Page, over: Record<string, unknown> = {}) {
	const state = updateStatus(over);
	let requested: { target?: string } | null = null;
	await page.route('**/api/v1/system/update', async (route: Route) => {
		const req = route.request();
		if (req.method() === 'POST') {
			const body = req.postDataJSON() as { target_version?: string };
			requested = { target: body.target_version };
			const r: Request = {
				id: 7,
				requested_at: new Date().toISOString(),
				requested_by: 'admin',
				status: 'pending',
				log: '',
				...(body.target_version ? { target_version: body.target_version } : {})
			};
			state.requests = [r];
			state.can_request = false;
			await route.fulfill({ status: 202, json: r });
			return;
		}
		const r = state.requests[0];
		if (r?.status === 'pending') {
			r.status = 'running';
			r.log = '12:00:01 Update request 7 from admin taken by the updater.\n12:00:02 Updating from v2.0.0 to v2.1.0.\n';
		} else if (r?.status === 'running') {
			r.status = 'done';
			r.finished_at = new Date().toISOString();
			r.log += '12:00:40 pihole-rbac v2.1.0 is running and healthy.\n';
			Object.assign(state, { current_version: '2.1.0', update_available: false, can_request: true });
		}
		await route.fulfill({ json: state });
	});
	return { requested: () => requested };
}

const card = (page: Page, name: string) => page.locator('[data-slot="card"]').filter({ has: page.getByRole('heading', { name }) });

test('admin: the version, the update check being off, and the secrets', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/system');
	await expect(page).toHaveTitle('System · pihole-rbac');

	const version = (await (await page.request.get('/api/v1/system/version')).json()) as { version: string };
	await expect(page.getByTestId('running-version')).toContainText(version.version);

	const updates = card(page, 'Updates');
	await expect(updates).toContainText('The update check is off');
	await expect(updates).toContainText('Install a new release the same way this one was installed.');
	await expect(updates.getByRole('button', { name: 'Update now' })).toHaveCount(0);
	await expect(updates.getByRole('button', { name: 'Check now' })).toHaveCount(0);

	const secrets = card(page, 'Secrets');
	await expect(secrets.locator('[data-secret="PIHOLE_RBAC_SECRET_KEY"]')).toContainText('From the environment');
	const pihole1 = state.seeded.fixture.instances[0].env_name;
	await expect(secrets.locator(`[data-secret="PIHOLE_RBAC_INSTANCE_${pihole1}_PASSWORD"]`)).toContainText('Instance password');
	await secrets.getByRole('button', { name: 'Reload secrets' }).click();
	await expect(page.getByText('Secrets reloaded: nothing had changed.')).toBeVisible();

	await expect(card(page, 'Restart').getByRole('button', { name: 'Restart the app' })).toBeVisible();
});

test('without app.update or config.reload there is no System page', async ({ page, state }) => {
	let asked = false;
	await page.route('**/api/v1/system/update', (route) => {
		asked = true;
		return route.continue();
	});
	await openAs(page, state.seeded.fixture.no_instances, '/admin/system');
	await expect(page.getByText('You need the app.update or config.reload permission')).toBeVisible();
	await page.getByRole('button', { name: 'Admin' }).click();
	await expect(page.getByRole('menuitem', { name: 'System' })).toHaveCount(0);
	expect(asked, 'the update status was asked for without app.update').toBe(false);
});

test('an update on LXC: the banner, Update now, its progress and the result', async ({ page, state }) => {
	const updater = await fakeUpdater(page);
	await openAs(page, state.seeded.fixture.admin, '/admin/audit');

	// The banner, on any page, until it is dismissed for this release.
	const banner = page.getByRole('alert', { name: 'Update available' });
	await expect(banner).toContainText('pihole-rbac v2.1.0 is available (this is v2.0.0).');
	await expect(banner.getByRole('link', { name: "What's new" })).toHaveAttribute('href', /releases\/tag\/v2\.1\.0$/);
	await banner.getByRole('button', { name: 'Dismiss until the next release' }).click();
	await expect(banner).toHaveCount(0);
	await page.reload();
	await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible();
	await expect(banner).toHaveCount(0);

	await page.goto('/admin/system');
	const updates = card(page, 'Updates');
	await expect(updates).toContainText('v2.1.0 is available; this is v2.0.0.');

	// A version that isn't a tag is caught before anything is sent.
	const version = updates.getByLabel('Version (optional)');
	await version.fill('2.1');
	await expect(updates).toContainText('A release tag such as v2.1.0');
	await expect(updates.getByRole('button', { name: 'Update now' })).toBeDisabled();
	await version.fill('');

	await updates.getByRole('button', { name: 'Update now' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('Update to v2.1.0?');
	await confirm.getByRole('button', { name: 'Update now' }).click();
	expect(updater.requested()).toEqual({ target: undefined }); // the latest release: no version sent

	// Progress, then the result, read every two seconds.
	const history = updates.getByRole('list', { name: 'Update history' });
	await expect(history).toContainText('Updating from v2.0.0 to v2.1.0.');
	await expect(page.getByText('Update finished: running v2.1.0.')).toBeVisible({ timeout: 10_000 });
	await expect(history.getByText('Done')).toBeVisible();
	await expect(history).toContainText('is running and healthy');
	await expect(updates).toContainText('The server now runs v2.1.0. Reload the page');
	await expect(updates.getByRole('button', { name: 'Update now' })).toBeVisible();
});

test('a prerelease can be asked for by name', async ({ page, state }) => {
	const updater = await fakeUpdater(page, { current_version: '2.0.0', update_available: false, latest: undefined });
	await openAs(page, state.seeded.fixture.admin, '/admin/system');
	const updates = card(page, 'Updates');
	await updates.getByLabel('Version (optional)').fill(' v2.1.0-rc.1 ');
	await updates.getByRole('button', { name: 'Update now' }).click();
	await expect(page.getByRole('alertdialog')).toContainText('Update to v2.1.0-rc.1?');
	await page.getByRole('alertdialog').getByRole('button', { name: 'Update now' }).click();
	await expect(updates.getByRole('list', { name: 'Update history' })).toContainText('To v2.1.0-rc.1');
	expect(updater.requested()).toEqual({ target: 'v2.1.0-rc.1' });
});

test('Docker: the commands to run, and no Update now', async ({ page, state }) => {
	await fakeUpdater(page, { install: 'docker' });
	await openAs(page, state.seeded.fixture.admin, '/admin/system');
	const updates = card(page, 'Updates');
	await expect(updates).toContainText('docker compose pull');
	await expect(updates).toContainText('docker compose up -d');
	await expect(updates.getByRole('button', { name: 'Update now' })).toHaveCount(0);
});

test('restart: asks first, then waits until the app answers again', async ({ page, state }) => {
	let restarted = false;
	let downFor = 2; // version reads that fail after the restart, as while the process is down
	await page.route('**/api/v1/system/restart', (route) => {
		restarted = true;
		return route.fulfill({ status: 202, body: '' });
	});
	await page.route('**/api/v1/system/version', (route) => {
		if (restarted && downFor > 0) {
			downFor--;
			return route.abort('connectionrefused');
		}
		return route.continue();
	});
	await openAs(page, state.seeded.fixture.admin, '/admin/system');
	const restart = card(page, 'Restart');
	await restart.getByRole('button', { name: 'Restart the app' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText('Restart pihole-rbac?');
	// The seeded server doesn't set PIHOLE_RBAC_INSTALL, so the dialog warns that nothing may start it again.
	await expect(confirm).toContainText('it stays stopped until it is started by hand');
	await confirm.getByRole('button', { name: 'Restart' }).click();
	await expect(restart).toContainText('Restarting… waiting for the app to answer again.');
	await expect(page.getByText('pihole-rbac has restarted.')).toBeVisible({ timeout: 15_000 });
	expect(restarted).toBe(true);
	expect(downFor).toBe(0);
});
