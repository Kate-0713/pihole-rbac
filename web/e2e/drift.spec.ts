// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Drift, against the seeded server: pihole1 has three list entries, two clients and a "kids" group, and pihole2 has
// none of them, so a mirrored group of the two, with pihole1 as its primary, differs at once. The test makes the
// group through the API and removes it in a finally.
import { apiWrite, expect, openAs, test } from './fixtures.js';

test("a drifted group's differences are listed, and its pages say it has drifted", async ({ page, state }) => {
	const [one, two] = state.seeded.fixture.instances;
	await openAs(page, state.seeded.fixture.admin, '/dashboard');
	const res = await apiWrite(page, 'POST', '/api/v1/instance-groups', {
		name: 'e2e drift',
		mode: 'mirrored',
		members: [one.id, two.id],
		primary_instance_id: one.id
	});
	const id = (await res.json()).id;
	try {
		// The Drift page is offered for the group, not for an instance.
		await page.goto(`/domains?target=i-${one.id}`);
		const nav = page.getByRole('navigation', { name: 'Main' });
		await expect(nav.getByRole('link', { name: 'Drift' })).toHaveCount(0);
		await page.goto(`/dashboard?target=g-${id}`);
		await nav.getByRole('link', { name: 'Drift' }).click();
		await expect(page).toHaveURL(`/drift?target=g-${id}`);
		await expect(page).toHaveTitle('e2e drift · Drift · pihole-rbac');

		// Checked now, whether or not the server has already got to it.
		await page.getByRole('button', { name: 'Check now' }).click();
		await expect(page.getByText('Drifted', { exact: true })).toBeVisible();
		await expect(page.getByText('Members differ from the primary in 3 domain list entries, 2 clients and 1 Pi-hole group.')).toBeVisible();
		const domains = page.getByRole('region', { name: 'Domain lists' });
		await expect(domains.getByRole('row')).toHaveCount(4); // the header and three entries
		await expect(domains.getByRole('row', { name: /games\.example/ })).toContainText('Missing');
		await expect(page.getByRole('region', { name: 'Clients' }).getByRole('row', { name: /printer|10\.0\.1\.5/ })).toContainText('Missing');
		await expect(page.getByRole('region', { name: 'Pi-hole groups' }).getByRole('row', { name: /kids/ })).toContainText('Missing');

		// The domains and clients pages of the group say so, and link here.
		await page.goto(`/domains?target=g-${id}`);
		const badge = page.getByRole('link', { name: 'Drifted' });
		await expect(badge).toBeVisible();
		await badge.click();
		await expect(page).toHaveURL(`/drift?target=g-${id}`);
		await page.goto(`/clients?target=g-${id}`);
		await expect(page.getByRole('link', { name: 'Drifted' })).toBeVisible();

		// An instance's page has no badge.
		await page.goto(`/domains?target=i-${one.id}`);
		await expect(page.getByRole('link', { name: /Drifted|In sync/ })).toHaveCount(0);
	} finally {
		await apiWrite(page, 'DELETE', `/api/v1/instance-groups/${id}`);
	}
});

test('the drift page explains itself for an instance', async ({ page, state }) => {
	await openAs(page, state.seeded.fixture.admin, `/drift?target=i-${state.seeded.fixture.instances[0].id}`);
	await expect(page.getByText('Drift is about mirrored groups.')).toBeVisible();
});
