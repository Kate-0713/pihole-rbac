// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Mirrored groups as targets, against the seeded server: pihole1 and pihole2 on fake Pi-holes, pihole3 on an address
// nothing listens on, so it always fails. Each test makes its group through the API and removes it, and anything it
// added, in a finally: the other tests expect no groups and the fakes as seeded.
import type { Page } from '@playwright/test';
import { apiWrite, expect, openAs, picker, test, type State } from './fixtures.js';

async function makeGroup(page: Page, state: State, name: string, members: number[], primary: number): Promise<number> {
	const res = await apiWrite(page, 'POST', '/api/v1/instance-groups', {
		name,
		mode: 'mirrored',
		members,
		primary_instance_id: primary
	});
	return (await res.json()).id;
}

test('a mirrored group can be picked, and its dashboard and query log show every member', async ({ page, state }) => {
	const [one, two, three] = state.seeded.fixture.instances;
	await openAs(page, state.seeded.fixture.admin, '/dashboard');
	const id = await makeGroup(page, state, 'e2e site', [one.id, two.id, three.id], one.id);
	try {
		await page.reload();
		await picker(page).click();
		await expect(page.getByText('Mirrored groups')).toBeVisible();
		await page.getByRole('option', { name: /e2e site/ }).click();
		await expect(page).toHaveURL(`/dashboard?target=g-${id}`);
		await expect(page.getByRole('option')).toHaveCount(0);

		// Each member with its own state; pihole3 doesn't answer, and the totals are the other two's.
		const members = page.getByRole('list', { name: 'Members' });
		await expect(members.getByRole('listitem')).toHaveCount(3);
		await expect(members.getByRole('listitem').first()).toContainText('pihole1');
		await expect(members.getByRole('listitem').first()).toContainText('Primary');
		await expect(members.getByRole('listitem').nth(2)).toContainText("Pi-hole \"pihole3\" didn't respond.");
		await expect(page.getByText('mirrored group of 3')).toBeVisible();

		// The query log merges the members' entries, names the instance of each, and says who is missing.
		await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Query log' }).click();
		await expect(page.getByRole('columnheader', { name: 'Instance' })).toBeVisible();
		await expect(page.getByRole('cell', { name: 'pihole1', exact: true }).first()).toBeVisible();
		await expect(page.getByText("Not included, because it didn't answer: pihole3")).toBeVisible();
	} finally {
		await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${id}`);
	}
});

test('a write that fails on one member shows each member, and retries only the failed one', async ({ page, state }) => {
	const [one, two, three] = state.seeded.fixture.instances;
	await openAs(page, state.seeded.fixture.admin, '/dashboard');
	const id = await makeGroup(page, state, 'e2e retry', [one.id, two.id, three.id], one.id);
	const domain = 'e2e-group-retry.example';
	try {
		await page.goto(`/domains?target=g-${id}`);
		await page.getByRole('button', { name: 'Add a domain' }).click();
		const dialog = page.getByRole('dialog');
		await dialog.getByLabel('Domain', { exact: true }).fill(domain);
		await dialog.getByRole('button', { name: 'Add' }).click();
		await expect(dialog).toHaveCount(0);

		const results = page.getByRole('list', { name: 'Results per member' });
		await expect(page.getByText(`${domain} added to the deny list on 2 of 3 members`)).toBeVisible();
		await expect(results.getByRole('listitem')).toHaveText([/^pihole1\s*Done/, /^pihole2\s*Done/, /^pihole3\s*(Failed|Not reached)/]);

		// The retry names pihole3 alone; it still fails, so the panel stays, with pihole3's new result.
		const retried = page.waitForRequest((r) => r.method() === 'POST' && r.url().includes('/domains?members='));
		await page.getByRole('button', { name: 'Retry the failed member' }).click();
		expect(new URL((await retried).url()).searchParams.getAll('members')).toEqual([String(three.id)]);
		await expect(results.getByRole('listitem')).toHaveCount(3);
		await expect(results.getByRole('listitem').nth(2)).toContainText('pihole3');
		await page.getByRole('button', { name: 'Dismiss' }).last().click();
		await expect(results).toHaveCount(0);

		// The list is the primary's, and has the entry.
		await expect(page.getByRole('cell', { name: domain, exact: true }).first()).toBeVisible();
	} finally {
		const session = await page.request.get('/api/v1/auth/session');
		const { csrf_token } = await session.json();
		await page.request.fetch(`/api/v1/targets/g-${id}/domains`, {
			method: 'DELETE',
			data: { domain, type: 'deny', kind: 'exact' },
			headers: { 'X-CSRF-Token': csrf_token, Origin: new URL(page.url()).origin }
		});
		await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${id}`);
	}
});

test('a member of a mirrored group warns before it is changed alone', async ({ page, state }) => {
	const [one, two] = state.seeded.fixture.instances;
	await openAs(page, state.seeded.fixture.admin, '/dashboard');
	const id = await makeGroup(page, state, 'e2e pair', [one.id, two.id], one.id);
	try {
		await page.goto(`/domains?target=i-${one.id}`);
		await expect(page.getByText('pihole1 is a member of the mirrored group e2e pair')).toBeVisible();
		await page.getByRole('link', { name: 'work on e2e pair' }).click();
		await expect(page).toHaveURL(`/domains?target=g-${id}`);
		await expect(page.getByText('is a member of the mirrored group')).toHaveCount(0);

		// alice can only view pihole1's lists, so she isn't warned about changing them.
		await page.context().clearCookies();
		await openAs(page, state.seeded.fixture.one_instance, `/domains?target=i-${one.id}`);
		await expect(page.getByRole('table')).toBeVisible();
		await expect(page.getByText('is a member of the mirrored group')).toHaveCount(0);
	} finally {
		await page.context().clearCookies();
		await openAs(page, state.seeded.fixture.admin, '/dashboard');
		await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${id}`);
	}
});

test("a group whose primary is down says why its lists can't be shown", async ({ page, state }) => {
	const [, two, three] = state.seeded.fixture.instances;
	await openAs(page, state.seeded.fixture.admin, '/dashboard');
	const id = await makeGroup(page, state, 'e2e down', [two.id, three.id], three.id);
	try {
		await page.goto(`/domains?target=g-${id}`);
		const alert = page.getByRole('alert');
		await expect(alert).toContainText('It\'s the primary of "e2e down".');
		await expect(alert).toContainText("lists are read from its primary alone");
		// The dashboard still shows the member that answered.
		await page.goto(`/dashboard?target=g-${id}`);
		await expect(page.getByRole('list', { name: 'Members' }).getByRole('listitem')).toHaveCount(2);
		await expect(page.getByText('Couldn\'t read the dashboard')).toHaveCount(0);
	} finally {
		await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${id}`);
	}
});
