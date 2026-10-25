// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The client reset admin page, against the seeded server. pihole1's client 10.0.0.0/24 has the comment "lab subnet"
// and is in the Default group; the rule here puts clients whose comment starts with "lab " in kids. The test puts the
// client, the rules and the schedule back afterwards.
import { apiWrite, expect, openAs, test } from './fixtures.js';

test('rules, the schedule and the runs, on the admin page', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/client-reset');
	await expect(page.getByRole('heading', { name: 'Client reset', level: 1 })).toBeVisible();
	await expect(page.getByText('No rules yet, so nothing is reset.')).toBeVisible();
	await expect(page.getByText('No runs yet.')).toBeVisible();
	const general = await (await page.request.get('/api/v1/settings/general')).json();

	try {
		// A rule, with its problems caught before saving.
		await page.getByRole('button', { name: 'Edit rules' }).click();
		const dialog = page.getByRole('dialog');
		const save = dialog.getByRole('button', { name: 'Save' });
		await expect(dialog.getByText('Rule 1: choose an instance or mirrored group.')).toBeVisible();
		await expect(save).toBeDisabled();
		await dialog.getByRole('combobox', { name: 'Instance or mirrored group' }).click();
		await page.getByRole('option', { name: /^pihole1/ }).click();
		await dialog.getByLabel('Comment starts with').fill('lab ');
		await expect(dialog.getByText('Rule 1: name at least one Pi-hole group.')).toBeVisible();
		await dialog.getByLabel('Pi-hole groups, separated by commas').fill('kids');
		await save.click();
		await expect(page.getByText('Client reset rules saved.')).toBeVisible();
		await expect(dialog).toHaveCount(0);
		const rules = page.getByRole('list', { name: 'Rules' });
		await expect(rules).toContainText('pihole1');
		await expect(rules).toContainText('"lab " → kids');

		// The schedule, with its next run worked out in the browser.
		await page.getByLabel('Run daily').check();
		await page.getByLabel('Run at', { exact: true }).fill('02:30');
		await page.getByLabel('Time zone').fill('Mars/Olympus');
		await expect(page.getByText(`"Mars/Olympus" isn't a time zone`)).toBeVisible();
		await page.getByLabel('Time zone').fill('Europe/London');
		await expect(page.getByText(/^Next run .*\(Europe\/London\)/)).toBeVisible();
		await page.getByRole('button', { name: 'Save' }).click();
		await expect(page.getByText('Client reset will run daily at 02:30 (Europe/London).')).toBeVisible();
		const saved = await (await page.request.get('/api/v1/settings/general')).json();
		expect(saved.client_reset_schedule).toEqual({ enabled: true, time: '02:30', time_zone: 'Europe/London' });
		expect(saved.session_lifetime_minutes).toBe(general.session_lifetime_minutes);

		// A run (started here through the API; the dashboard's button comes next), then the history.
		const run = await (await apiWrite(page, 'POST', '/api/v1/targets/i-1/client-reset/run')).json();
		expect(run.status).toBe('ok');
		await page.getByRole('button', { name: 'Refresh' }).click();
		const row = page.locator(`[data-run="${run.id}"]`);
		await expect(row).toContainText('pihole1');
		await expect(row).toContainText('admin');
		await expect(row).toContainText('1 client reset');
		await expect(row).toContainText('Done');
		await page.getByRole('button', { name: 'Show the details of the run of pihole1' }).click();
		const details = page.locator(`#reset-run-${run.id}`).getByRole('region', { name: 'pihole1' });
		await expect(details).toContainText('10.0.0.0/24');
		await expect(details).toContainText('Default → kids');
		await expect(details).not.toContainText('already in');
	} finally {
		await apiWrite(page, 'PATCH', '/api/v1/targets/i-1/clients', { client: '10.0.0.0/24', comment: 'lab subnet', groups: [0] });
		await apiWrite(page, 'PUT', '/api/v1/client-reset/rules', { rules: [] });
		await apiWrite(page, 'PUT', '/api/v1/settings/general', {
			session_lifetime_minutes: general.session_lifetime_minutes,
			idle_timeout_minutes: general.idle_timeout_minutes,
			client_reset_schedule: general.client_reset_schedule
		});
	}
});

test('the page needs settings.manage', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/admin/client-reset');
	await expect(page.getByText('You need the settings.manage permission to manage client reset.')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Edit rules' })).toHaveCount(0);
});

// The dashboard's card: a preview before running, the results afterwards, and the last run on the card.
test('running client reset from the dashboard, after a preview', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await apiWrite(page, 'PUT', '/api/v1/client-reset/rules', {
		rules: [{ scope: 'instance', id: 1, comment_prefix: 'lab ', group_match: 'names', pihole_groups: ['kids'] }]
	});
	try {
		await page.reload();
		const card = page.locator('[data-slot="card"]', { has: page.getByText('Client reset', { exact: true }) });
		await expect(card).toContainText('1 rule · change them');
		// The test above ran pihole1 already, so the card shows that run until this one replaces it.

		await card.getByRole('button', { name: 'Run now…' }).click();
		const dialog = page.getByRole('dialog');
		await expect(dialog).toContainText('Would reset 1 client on pihole1.');
		const pihole1 = dialog.getByRole('region', { name: 'pihole1' });
		await expect(pihole1).toContainText('Would reset:');
		await expect(pihole1).toContainText('10.0.0.0/24');
		await expect(pihole1).toContainText('Default → kids');
		await dialog.getByRole('button', { name: 'Run now' }).click();
		await expect(dialog.getByRole('heading', { name: 'Client reset done' })).toBeVisible();
		await expect(dialog).toContainText('On pihole1: 1 client reset.');
		await expect(dialog.getByRole('region', { name: 'pihole1' })).toContainText('Reset:');
		await expect(page.getByText('Client reset on pihole1: 1 client reset.')).toBeVisible();
		await dialog.getByRole('button', { name: 'OK' }).click();

		const last = card.getByLabel('Last run');
		await expect(last).toContainText('by admin:');
		await expect(last).toContainText('1 client reset');
		await expect(last).toContainText('Done');

		// Run again: the preview says there's nothing to do now.
		await card.getByRole('button', { name: 'Run now…' }).click();
		await expect(dialog).toContainText('Nothing to reset: every matching client is already in its groups.');
		await expect(dialog).toContainText('1 matching client was already in its groups.');
		await dialog.getByRole('button', { name: 'Cancel' }).click();
	} finally {
		await apiWrite(page, 'PATCH', '/api/v1/targets/i-1/clients', { client: '10.0.0.0/24', comment: 'lab subnet', groups: [0] });
		await apiWrite(page, 'PUT', '/api/v1/client-reset/rules', { rules: [] });
	}
});

test("the card says when there are no rules, and isn't shown without clientreset.run", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-2');
	await expect(page.getByText("No client reset rules are set here, so there's nothing to run.")).toBeVisible();
	await expect(page.getByRole('link', { name: 'Add rules' })).toHaveAttribute('href', '/admin/client-reset');
	await expect(page.getByRole('button', { name: 'Run now…' })).toHaveCount(0);

	await page.context().clearCookies();
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await expect(page.getByText('Blocking', { exact: true })).toBeVisible();
	await expect(page.getByText('Client reset', { exact: true })).toHaveCount(0);
});
