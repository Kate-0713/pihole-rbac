// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { GravityRun, PiholeList } from '#lib/lists.js';
import type { PiholeGroup } from '#lib/pihole.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_listsKey) reads the lists again, after a change or a gravity run.
export const _listsKey = 'app:lists';

type Data = {
	lists: PiholeList[];
	groups: PiholeGroup[];
	error: string | null;
	allowed: boolean;
	primaryDown?: boolean;
	drifted?: boolean;
	gravityLastUpdate?: string;
	// For a mirrored group: how each member answered, for the ones that couldn't be read.
	members?: { instance: string; status: string; error?: { message: string } }[];
	// The target's latest gravity run, so a page opened during one shows it.
	latestRun: GravityRun | null;
};

// Reading the lists needs lists.view, and so does following a gravity run.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_listsKey);
	const { target } = await parent();
	const empty = { lists: [], groups: [], latestRun: null };
	if (!target || !can('lists.view', target)) return { ...empty, error: null, allowed: false };

	const params = { params: { path: { target } }, fetch };
	try {
		const [list, groups, latestRun] = await Promise.all([
			unwrap(api.GET('/api/v1/targets/{target}/lists', params)),
			unwrap(api.GET('/api/v1/targets/{target}/groups', params)),
			// A 404 just means no run since the app started.
			unwrap(api.GET('/api/v1/targets/{target}/gravity', params)).catch((e) => {
				if (e instanceof ApiError && e.status === 404) return null;
				throw e;
			})
		]);
		return {
			lists: list.lists,
			groups: groups.groups,
			error: null,
			allowed: true,
			drifted: list.drifted,
			gravityLastUpdate: list.gravity_last_update,
			members: list.members,
			latestRun
		};
	} catch (e) {
		if (e instanceof ApiError) return { ...empty, error: e.message, allowed: true, primaryDown: e.details.primary === true };
		throw e;
	}
};
