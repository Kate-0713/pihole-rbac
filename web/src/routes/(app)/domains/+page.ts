// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { Domain } from '#lib/domains.js';
import type { PiholeGroup } from '#lib/pihole.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_domainsKey) reads the lists again, after a change. (An underscore, because a +page.ts may only export
// SvelteKit's own names and names starting with one.)
export const _domainsKey = 'app:domains';

type Data = {
	domains: Domain[];
	groups: PiholeGroup[];
	// Set when there's nothing to show, with the reason.
	error: string | null;
	allowed: boolean;
	// Set when the target is a mirrored group whose primary couldn't be read: its lists come from the primary alone.
	primaryDown?: boolean;
	// For a mirrored group: whether its members' lists differed from the primary's at the last drift check.
	drifted?: boolean;
};

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_domainsKey);
	const { target } = await parent();
	const empty = { domains: [], groups: [] };
	if (!target) return { ...empty, error: null, allowed: false };
	// The server would refuse with a 403; asking first gives a plainer message and saves the request.
	if (!can('domains.view', target)) return { ...empty, error: null, allowed: false };

	const params = { params: { path: { target } }, fetch };
	try {
		// Both from the same Pi-hole, in parallel: the groups name the IDs in each entry.
		const [list, groups] = await Promise.all([
			unwrap(api.GET('/api/v1/targets/{target}/domains', params)),
			unwrap(api.GET('/api/v1/targets/{target}/groups', params))
		]);
		return { domains: list.domains, groups: groups.groups, error: null, allowed: true, drifted: list.drifted };
	} catch (e) {
		// A Pi-hole that is down is shown on the page, as on the dashboard.
		if (e instanceof ApiError) return { ...empty, error: e.message, allowed: true, primaryDown: e.details.primary === true };
		throw e;
	}
};
