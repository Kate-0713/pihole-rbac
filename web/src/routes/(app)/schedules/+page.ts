// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { ScheduleList } from '#lib/schedules.js';
import type { PageLoad } from './$types';

// invalidate(_schedulesKey) reads the schedules again, after a change.
export const _schedulesKey = 'app:schedules';

type Data = {
	list: ScheduleList | null;
	// The target's Pi-hole group names, for the dialog's picker; empty when they can't be read (the dialog still works
	// for blocking windows, and the server checks the group anyway).
	groups: string[];
	error: string | null;
	allowed: boolean;
};

// The schedules come from the app's database, so they load even when the Pi-holes don't answer. The groups are read
// from the Pi-hole (a mirrored group's primary) alongside, and only for someone who can schedule a group.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_schedulesKey);
	const { target } = await parent();
	if (!target || !can('schedules.manage', target)) return { list: null, groups: [], error: null, allowed: false };
	const groups = can('piholegroups.edit', target)
		? unwrap(api.GET('/api/v1/targets/{target}/groups', { params: { path: { target } }, fetch }))
				.then((g) => g.groups.map((x) => x.name))
				.catch((): string[] => [])
		: Promise.resolve([]);
	try {
		const list = await unwrap(api.GET('/api/v1/targets/{target}/schedules', { params: { path: { target } }, fetch }));
		return { list, groups: await groups, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { list: null, groups: [], error: e.message, allowed: true };
		throw e;
	}
};
