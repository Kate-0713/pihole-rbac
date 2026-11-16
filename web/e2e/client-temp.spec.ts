// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Temporary client group changes (v2.6.0), against the seeded server's pihole1 (i-1). Its fake Pi-hole has the client
// 10.0.0.0/24 in Default and a "kids" group. A change lasts an hour or more here, so the app's own scheduler never
// reverts one while a test runs; each test ends what it started, and the setting tests put the limits back.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const CLIENT = '10.0.0.0/24';
const row = (page: Page) => page.getByRole('row').filter({ hasText: CLIENT });
const moveButton = (page: Page) => page.getByRole('button', { name: `Move ${CLIENT} to other groups for a while` });

type Listed = { changes: { id: number; status: string; starts_at: string; ends_at: string }[] };

// Ends every active change on i-1, in case a test stopped half-way.
async function endAll(page: Page) {
	const res = await page.request.get('/api/v1/targets/i-1/clients/temporary');
	if (!res.ok()) return;
	for (const c of ((await res.json()) as Listed).changes.filter((c) => c.status === 'active')) {
		await apiWrite(page, 'POST', `/api/v1/targets/i-1/clients/temporary/${c.id}/end`);
	}
}

async function start(page: Page, minutes = 60) {
	await apiWrite(page, 'POST', '/api/v1/targets/i-1/clients/temporary', {
		client: CLIENT,
		groups: ['Default', 'kids'],
		duration_minutes: minutes,
		reason: 'e2e'
	});
}

// Changes the two temporary-change settings, keeping the session settings the save asks for.
async function setLimits(page: Page, patch: { client_temp_max_minutes?: number; client_temp_reason_required?: boolean }) {
	const g = (await (await page.request.get('/api/v1/settings/general')).json()) as {
		session_lifetime_minutes: number;
		idle_timeout_minutes: number;
	};
	await apiWrite(page, 'PUT', '/api/v1/settings/general', {
		session_lifetime_minutes: g.session_lifetime_minutes,
		idle_timeout_minutes: g.idle_timeout_minutes,
		...patch
	});
}

test('moving a client to other groups for an hour, then putting it back', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await endAll(page);
	await page.reload();
	try {
		await moveButton(page).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog).toContainText(`${CLIENT} on pihole1. The app puts it back when the time is up.`);
		await expect(dialog).toContainText('The client returns to: Default.');

		// Nothing to save until the groups differ, and the reason is asked for.
		const save = dialog.getByRole('button', { name: 'Change groups' });
		await expect(save).toBeDisabled();
		await expect(dialog).toContainText("These are the client's groups already");
		await dialog.getByLabel('kids').click();
		await expect(save).toBeDisabled();
		await expect(dialog).toContainText('Say why');
		await dialog.getByLabel('Reason').fill('homework');
		await expect(dialog.getByRole('button', { name: '1 hour' })).toHaveAttribute('aria-pressed', 'true');
		await expect(save).toBeEnabled();
		await save.click();

		await expect(page.getByText(new RegExp(`${CLIENT.replace(/[./]/g, '\\$&')}'s groups changed until .* on pihole1\\.`))).toBeVisible();
		await expect(dialog).toHaveCount(0);
		const lab = row(page);
		await expect(lab).toContainText('Default, kids');
		await expect(lab).toContainText('Temporary until');
		await expect(lab).toContainText('left');
		await expect(lab).toContainText('homework');
		// While it runs the row offers Extend and End now, not another start.
		await expect(moveButton(page)).toHaveCount(0);

		await page.getByRole('button', { name: `End the temporary change for ${CLIENT} now` }).click();
		await expect(page.getByText(`${CLIENT} is back in its groups on pihole1.`)).toBeVisible();
		await expect(lab).not.toContainText('Temporary until');
		await expect(lab).not.toContainText('kids');
		await expect(moveButton(page)).toBeVisible();
	} finally {
		await endAll(page);
	}
});

test('a change can be extended, and the Change dialog warns that its change is kept', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await endAll(page);
	try {
		await start(page, 60);
		await page.reload();
		await expect(row(page)).toContainText('Temporary until');

		await page.getByRole('button', { name: `Change ${CLIENT}`, exact: true }).click();
		await expect(page.getByRole('dialog')).toContainText('This client has a temporary change until');
		await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

		await page.getByRole('button', { name: `Extend the temporary change for ${CLIENT}` }).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog).toContainText(`${CLIENT} goes back to its groups at`);
		await dialog.getByRole('button', { name: 'Add 1 hour' }).click();
		await dialog.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText(`${CLIENT} is changed until`)).toBeVisible();

		const list = (await (await page.request.get('/api/v1/targets/i-1/clients/temporary')).json()) as Listed;
		const c = list.changes.find((c) => c.status === 'active');
		expect(c).toBeTruthy();
		const length = (Date.parse(c!.ends_at) - Date.parse(c!.starts_at)) / 60_000;
		expect(length).toBeGreaterThan(118);
		expect(length).toBeLessThan(122);
	} finally {
		await endAll(page);
	}
});

test('the limit counts from the start, so an extension past it is refused and the presets fit it', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/clients?target=i-1');
	await endAll(page);
	try {
		await setLimits(page, { client_temp_max_minutes: 90 });
		await start(page, 60);
		await page.reload();

		await page.getByRole('button', { name: `Extend the temporary change for ${CLIENT}` }).click();
		const dialog = page.getByRole('dialog');
		// Another hour would end 2 hours after the start, beyond the 90 minutes.
		await expect(dialog.getByRole('button', { name: 'Add 1 hour' })).toBeDisabled();
		await expect(dialog.getByRole('button', { name: 'Add 15 minutes' })).toBeEnabled();
		await expect(dialog).toContainText('The latest it can end is');
		await dialog.getByRole('button', { name: 'Cancel' }).click();

		await endAll(page);
		await page.reload();
		await moveButton(page).click();
		const startDialog = page.getByRole('dialog');
		await expect(startDialog.getByRole('button', { name: '15 minutes' })).toBeVisible();
		await expect(startDialog.getByRole('button', { name: '1 hour' })).toBeVisible();
		await expect(startDialog.getByRole('button', { name: '4 hours' })).toHaveCount(0);
	} finally {
		await endAll(page);
		await setLimits(page, { client_temp_max_minutes: 10080 });
	}
});

test('the dashboard lists a running change', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await endAll(page);
	try {
		await start(page, 60);
		await page.reload();
		const card = page.getByRole('list', { name: 'Temporary changes' });
		await expect(card).toContainText(CLIENT);
		await expect(card).toContainText('left');
	} finally {
		await endAll(page);
	}
	await page.reload();
	await expect(page.getByRole('list', { name: 'Temporary changes' })).toHaveCount(0);
});

test('the reason can be made optional in the settings', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/settings');
	try {
		const card = page.getByRole('region', { name: 'Temporary client changes' });
		await expect(card.getByLabel('Ask for a reason when a change is started')).toBeChecked();
		await card.getByLabel('Ask for a reason when a change is started').uncheck();
		await card.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText(/Temporary client changes can now last up to/)).toBeVisible();

		await page.goto('/clients?target=i-1');
		await moveButton(page).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog.getByText('(optional)')).toBeVisible();
		await dialog.getByLabel('kids').click();
		await expect(dialog.getByRole('button', { name: 'Change groups' })).toBeEnabled();
	} finally {
		await setLimits(page, { client_temp_reason_required: true });
	}
});

test('a settings value outside the range is caught before sending', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/settings');
	const card = page.getByRole('region', { name: 'Temporary client changes' });
	await card.getByLabel('Hours').fill('0');
	await card.getByLabel('Minutes').fill('3');
	await expect(card).toContainText('5 minutes to 365 days');
	await expect(card.getByRole('button', { name: 'Save' })).toBeDisabled();
});

test('without clients.edit the list shows changes but offers none', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/clients?target=i-1');
	await expect(page.getByRole('button', { name: /^Move / })).toHaveCount(0);
	await expect(page.getByRole('button', { name: /^(Extend|End) / })).toHaveCount(0);
});
