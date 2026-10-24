// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The dashboard, against the seeded server. pihole1's fake Pi-hole reports fixed counters (see piholetest), and
// pihole3 is down. Blocking is shared state on the fake, so each test sets it first.
import type { Page } from '@playwright/test';
import { expect, openAs, test } from './fixtures.js';

// writeAs makes an API write with the page's session, as the SPA would: the session's CSRF token and our Origin.
async function apiWrite(page: Page, method: 'PUT' | 'POST', path: string, data?: unknown) {
	const session = await page.request.get('/api/v1/auth/session');
	expect(session.ok()).toBe(true);
	const { csrf_token } = await session.json();
	const origin = new URL(page.url()).origin;
	const res = await page.request.fetch(path, { method, data, headers: { 'X-CSRF-Token': csrf_token, Origin: origin } });
	expect(res.ok(), await res.text()).toBe(true);
	return res;
}

const setBlocking = (page: Page, enabled: boolean) =>
	apiWrite(page, 'PUT', '/api/v1/targets/i-1/blocking', { enabled });

const blockingCard = (page: Page) => page.locator('[data-slot="card"]', { hasText: 'Blocking' }).first();

test('shows the blocking state and both sets of counters', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await setBlocking(page, true);
	await page.reload();

	await expect(page).toHaveTitle('pihole1 · Dashboard · pihole-rbac');
	await expect(page.getByText('Blocking is on')).toBeVisible();

	const day = page.locator('[data-slot="card"]', { hasText: 'Last 24 hours' });
	await expect(day.getByRole('definition').first()).toHaveText('20,000');
	await expect(day).toContainText('4,000');
	await expect(day).toContainText('20.0%');

	const live = page.locator('[data-slot="card"]', { hasText: 'Live' });
	await expect(live).toContainText('1,000');
	await expect(live).toContainText('25.0%');
	await expect(live).toContainText('of 8 seen');
	await expect(live).toContainText('123,456');
});

test('turning blocking off for a while, and back on', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await setBlocking(page, true);
	await page.reload();

	const card = blockingCard(page);
	await card.getByRole('button', { name: 'Turn blocking off' }).click();
	await page.getByRole('menuitem', { name: 'For 5 minutes' }).click();
	await expect(page.getByText('Blocking turned off for 5 minutes on pihole1.')).toBeVisible();
	await expect(card).toContainText('Blocking is off');
	await expect(card).toContainText(/back on in [45]:\d\d/);

	// The server and the Pi-hole agree.
	const status = await (await page.request.get('/api/v1/targets/i-1/blocking')).json();
	expect(status).toEqual({ blocking: 'disabled', timer: 300 });

	await card.getByRole('button', { name: 'Turn blocking on' }).click();
	await expect(page.getByText('Blocking turned on on pihole1.')).toBeVisible();
	await expect(card).toContainText('Blocking is on');
});

test('turning blocking off until turned back on has no countdown', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await setBlocking(page, true);
	await page.reload();

	const card = blockingCard(page);
	await card.getByRole('button', { name: 'Turn blocking off' }).click();
	await page.getByRole('menuitem', { name: 'Until turned back on' }).click();
	await expect(card).toContainText('Blocking is off');
	await expect(card).not.toContainText('back on in');
	// Without a timer there's nothing to change, only turning it back on.
	await expect(card.getByRole('button', { name: 'Change how long' })).toHaveCount(0);
	await setBlocking(page, true);
});

test('the countdown runs, and the dashboard refreshes itself', async ({ page, state }) => {
	// Playwright's clock replaces the page's timers, so minutes can pass in an instant.
	await page.clock.install();
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await setBlocking(page, true);
	await page.reload();
	const card = blockingCard(page);
	await expect(card).toContainText('Blocking is on');

	// Someone else turns blocking off for 2 minutes; the next refresh, 15 seconds on, shows it without a reload.
	await apiWrite(page, 'PUT', '/api/v1/targets/i-1/blocking', { enabled: false, timer: 120 });
	await expect(card).toContainText('Blocking is on');
	await page.clock.fastForward('00:16');
	await expect(card).toContainText('Blocking is off');
	await expect(card).toContainText('back on in 2:00');

	// The fake Pi-hole's timer stands still, so check the countdown between refreshes.
	await page.clock.fastForward('00:10');
	await expect(card).toContainText(/back on in 1:5\d/);
	await setBlocking(page, true);
});

test('restarting DNS asks first', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await page.getByRole('button', { name: 'Restart DNS…' }).click();
	const confirm = page.getByRole('group', { name: 'Confirm DNS restart' });
	await expect(confirm).toContainText('Restart DNS on pihole1?');

	await confirm.getByRole('button', { name: 'Cancel' }).click();
	await expect(confirm).toHaveCount(0);

	await page.getByRole('button', { name: 'Restart DNS…' }).click();
	await confirm.getByRole('button', { name: 'Restart now' }).click();
	await expect(page.getByText('DNS restarted on pihole1.')).toBeVisible();
	await expect(confirm).toHaveCount(0);
});

test('a user without blocking.toggle or dns.restart sees the numbers but no controls', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await expect(page.getByText(/Blocking is (on|off)/)).toBeVisible();
	await expect(page.locator('[data-slot="card"]', { hasText: 'Last 24 hours' })).toContainText('20,000');
	await expect(page.getByRole('button', { name: /Turn blocking/ })).toHaveCount(0);
	await expect(page.getByRole('button', { name: 'Restart DNS…' })).toHaveCount(0);
	await expect(page.getByText('DNS resolver')).toHaveCount(0);
});

test('an instance that is down says so instead of showing numbers', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-3');
	await expect(page.getByRole('alert')).toContainText(`Couldn't read the dashboard: Pi-hole "pihole3"`);
	await expect(page.getByText('Last 24 hours')).toHaveCount(0);
	await expect(page.getByText(/Blocking is/)).toHaveCount(0);
	// The rest of the app still works: switching to an instance that is up shows its dashboard.
	await page.goto('/dashboard?target=i-1');
	await expect(page.getByRole('alert')).toHaveCount(0);
	await expect(page.getByText('Last 24 hours')).toBeVisible();
});
