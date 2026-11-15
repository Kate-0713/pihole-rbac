// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The Schedules page, against the seeded server's pihole1 (i-1), whose fake Pi-hole has a "kids" group. The schedules
// these tests save start in the future or have already been passed by, and a schedule acts only from its next edge,
// so the scheduler in the binary changes nothing while they run. Each test deletes what it added.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, test } from './fixtures.js';

const row = (page: Page, name: string) => page.locator(`tr[data-schedule="${name}"]`);

type Saved = { id: number; name: string };

// Deletes every schedule on i-1 whose name starts with "e2e", in case a test stopped half-way.
async function cleanUp(page: Page) {
	const res = await page.request.get('/api/v1/targets/i-1/schedules');
	if (!res.ok()) return;
	const list = (await res.json()) as { schedules: Saved[] };
	for (const s of list.schedules.filter((s) => s.name.startsWith('e2e'))) {
		await apiWrite(page, 'DELETE', `/api/v1/targets/i-1/schedules/${s.id}`);
	}
}

async function setGroupWindowMax(page: Page, minutes: number) {
	const g = (await (await page.request.get('/api/v1/settings/general')).json()) as {
		session_lifetime_minutes: number;
		idle_timeout_minutes: number;
	};
	await apiWrite(page, 'PUT', '/api/v1/settings/general', {
		session_lifetime_minutes: g.session_lifetime_minutes,
		idle_timeout_minutes: g.idle_timeout_minutes,
		schedule_group_window_max_minutes: minutes
	});
}

test('adding, switching off, changing and deleting a blocking window', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await cleanUp(page);
	await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Schedules' }).click();
	await expect(page).toHaveURL('/schedules?target=i-1');
	await expect(page).toHaveTitle('pihole1 · Schedules · pihole-rbac');
	await expect(page.getByText('No schedules.')).toBeVisible();

	await page.getByRole('button', { name: 'Add a schedule' }).click();
	const dialog = page.getByRole('dialog', { name: 'Add a schedule' });
	await dialog.getByLabel('Name').fill('e2e lab mornings');
	await dialog.getByLabel('Time zone').fill('UTC');
	// Weekdays 08:00 to 08:30 is what a new schedule starts with.
	await expect(dialog.getByText('30 minutes long, of at most 24 hours.')).toBeVisible();
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog).toBeHidden();

	const lab = row(page, 'e2e lab mornings');
	await expect(lab).toContainText('Blocking off');
	await expect(lab).toContainText('Weekdays 08:00–08:30');
	await expect(lab).toContainText('Starts');

	await lab.getByRole('button', { name: 'Switch off' }).click();
	await expect(lab).toContainText('Off');
	await expect(lab.getByRole('button', { name: 'Switch on' })).toBeVisible();
	await lab.getByRole('button', { name: 'Switch on' }).click();
	await expect(lab.getByRole('button', { name: 'Switch off' })).toBeVisible();

	await lab.getByRole('button', { name: 'Change' }).click();
	const change = page.getByRole('dialog', { name: 'Change schedule' });
	await change.getByLabel('To').fill('09:15');
	await expect(change.getByText('1 hour 15 minutes long')).toBeVisible();
	await change.getByRole('button', { name: 'Save' }).click();
	await expect(change).toBeHidden();
	await expect(lab).toContainText('Weekdays 08:00–09:15');

	await lab.getByRole('button', { name: 'Delete' }).click();
	const confirm = page.getByRole('alertdialog');
	await expect(confirm).toContainText("It won't act again.");
	await confirm.getByRole('button', { name: 'Delete' }).click();
	await expect(lab).toHaveCount(0);
});

test('a group window: the next day worked out, Default left out, the limit, and the dashboard line', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/schedules?target=i-1');
	await cleanUp(page);
	await page.getByRole('button', { name: 'Add a schedule' }).click();
	const dialog = page.getByRole('dialog', { name: 'Add a schedule' });
	await dialog.getByLabel('Name').fill('e2e bedtime');
	await dialog.getByLabel('What it does').click();
	await page.getByRole('option', { name: 'Group on' }).click();
	await dialog.getByLabel('Pi-hole group').click();
	await expect(page.getByRole('option', { name: 'Default' })).toHaveCount(0);
	await page.getByRole('option', { name: 'kids' }).click();
	for (const d of ['Saturday', 'Sunday']) await dialog.getByRole('checkbox', { name: d }).click();
	await dialog.getByLabel('From').fill('21:00');
	await dialog.getByLabel('To').fill('07:00');
	await dialog.getByLabel('Time zone').fill('UTC');
	// Ending before it starts means the next day, without asking.
	await expect(dialog.getByLabel('Ends')).toHaveValue('1');
	await expect(dialog.getByText('10 hours long, of at most 24 hours.')).toBeVisible();

	// Every day, a window into the day after next would overlap the next one: the form says so and won't save.
	await dialog.getByLabel('Ends').selectOption('2');
	await expect(dialog.getByText('The window is longer than the time until it starts again, so it would overlap itself.')).toBeVisible();
	await expect(dialog.getByRole('button', { name: 'Add' })).toBeDisabled();
	await dialog.getByLabel('Ends').selectOption('1');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog).toBeHidden();
	const bedtime = row(page, 'e2e bedtime');
	await expect(bedtime).toContainText('Group on');
	await expect(bedtime).toContainText('kids');
	await expect(bedtime).toContainText('Every day 21:00 to 07:00 the next day');

	// The same name is refused by the server, and the dialog shows why.
	await page.getByRole('button', { name: 'Add a schedule' }).click();
	await dialog.getByLabel('Name').fill('E2E BEDTIME');
	await dialog.getByLabel('Time zone').fill('UTC');
	await dialog.getByRole('button', { name: 'Add' }).click();
	await expect(dialog.getByText('There\'s already a schedule called "E2E BEDTIME" here.')).toBeVisible();
	await dialog.getByRole('button', { name: 'Cancel' }).click();

	// The dashboard says what's coming, with a link back.
	await page.goto('/dashboard?target=i-1');
	const card = page.getByRole('list', { name: 'Schedules' });
	// Before 21:00 UTC its next edge is ahead; after, its window is open (and a new schedule doesn't act on it).
	await expect(card).toContainText(/kids (turns on at|is on until)/);
	await expect(card).toContainText("(schedule 'e2e bedtime')");
	await page.getByRole('link', { name: 'Manage' }).click();
	await expect(page).toHaveURL('/schedules?target=i-1');

	// Lowering the limit below it marks it, and the page says what the limit is.
	await setGroupWindowMax(page, 360);
	await page.reload();
	await expect(page.getByText('A group window can be at most 6 hours long.')).toBeVisible();
	await expect(bedtime).toContainText('Over the limit');
	await setGroupWindowMax(page, 24 * 60);
	await cleanUp(page);
});

test('the blocking card says when a schedule has blocking off', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/dashboard?target=i-1');
	await cleanUp(page);
	// A window open now: every day, from an hour ago to an hour from now, in UTC. Saving it changes nothing on the
	// Pi-hole, as it acts from its next edge, so blocking is turned off by hand to stand for its start.
	const now = new Date();
	const hhmm = (d: Date) => d.toISOString().slice(11, 16);
	const start = hhmm(new Date(now.getTime() - 3600_000));
	const end = hhmm(new Date(now.getTime() + 3600_000));
	await apiWrite(page, 'POST', '/api/v1/targets/i-1/schedules', {
		name: 'e2e open now',
		kind: 'blocking_off',
		repeat: 'weekly',
		days: 127,
		start,
		end,
		end_days: end <= start ? 1 : 0,
		time_zone: 'UTC'
	});
	await apiWrite(page, 'PUT', '/api/v1/targets/i-1/blocking', { enabled: false, timer: 600 });
	try {
		await page.reload();
		await expect(page.getByText("Off for the schedule 'e2e open now' until")).toBeVisible();
		await expect(page.getByRole('list', { name: 'Schedules' })).toContainText("Blocking is off until");
	} finally {
		await apiWrite(page, 'PUT', '/api/v1/targets/i-1/blocking', { enabled: true });
		await cleanUp(page);
	}
});

test("a user without schedules.manage doesn't see the page", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.one_instance, '/dashboard?target=i-1');
	await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Schedules' })).toHaveCount(0);
	await page.goto('/schedules?target=i-1');
	await expect(page.getByText("You can't manage the schedules of pihole1.")).toBeVisible();
});

test('the group window limit on the Settings page', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/admin/settings');
	const card = page.getByRole('region', { name: 'Schedules' });
	await expect(card.getByLabel('Hours')).toHaveValue('24');
	await card.getByLabel('Hours').fill('0');
	await card.getByLabel('Minutes').fill('3');
	await expect(card.getByText('A group window can be limited to 5 minutes to 365 days.')).toBeVisible();
	await expect(card.getByRole('button', { name: 'Save' })).toBeDisabled();
	await card.getByLabel('Hours').fill('6');
	await card.getByLabel('Minutes').fill('30');
	await card.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByText('Group windows can now be up to 6 hours 30 minutes long.')).toBeVisible();
	await page.reload();
	await expect(card.getByLabel('Hours')).toHaveValue('6');
	await setGroupWindowMax(page, 24 * 60);
});

test("deleting a schedule's Pi-hole group lists the schedule and asks first", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/pihole-groups?target=i-1');
	await cleanUp(page);
	await apiWrite(page, 'POST', '/api/v1/targets/i-1/groups', { name: 'e2e sched', enabled: false });
	await apiWrite(page, 'POST', '/api/v1/targets/i-1/schedules', {
		name: 'e2e window',
		kind: 'group_enabled',
		pihole_group: 'e2e sched',
		repeat: 'weekly',
		days: 127,
		start: '21:00',
		end: '07:00',
		end_days: 1,
		time_zone: 'UTC'
	});
	try {
		await page.reload();
		await page.getByRole('button', { name: 'Delete e2e sched' }).click();
		const confirm = page.getByRole('alertdialog');
		await expect(confirm.locator('[data-references]')).toContainText('Schedule e2e window on pihole1, enables: e2e sched');
		await confirm.getByRole('button', { name: 'Delete anyway' }).click();
		await expect(page.getByText("The app still refers to e2e sched: 1 schedule. They're left for you to fix.")).toBeVisible();
		// The schedule stays, for someone to point at another group or delete.
		await page.goto('/schedules?target=i-1');
		await expect(row(page, 'e2e window')).toContainText('e2e sched');
	} finally {
		await cleanUp(page);
		const { groups } = (await (await page.request.get('/api/v1/targets/i-1/groups')).json()) as { groups: { name: string }[] };
		if (groups.some((g) => g.name === 'e2e sched')) await apiWrite(page, 'DELETE', '/api/v1/targets/i-1/groups?confirm=true', { name: 'e2e sched' });
	}
});

test("a one-off's end stays put when the start shows an error", async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, '/schedules?target=i-1');
	await page.getByRole('button', { name: 'Add a schedule' }).click();
	const dialog = page.getByRole('dialog', { name: 'Add a schedule' });
	await dialog.getByLabel('Name').fill('e2e layout');
	await dialog.getByText('Once').click();
	const endDate = dialog.getByLabel('End date');
	await endDate.fill('2020-01-01');
	await dialog.getByLabel('End time').fill('09:00');
	const before = await endDate.boundingBox();
	await dialog.getByLabel('Start date').fill('2020-01-01');
	await dialog.getByLabel('Start time').fill('08:00');
	await expect(dialog.getByText('A one-off schedule has to start in the future.')).toBeVisible();
	expect((await endDate.boundingBox())?.y).toBe(before?.y);
});
