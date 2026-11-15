// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { PiholeGroup } from '#lib/pihole.js';
import { canAny } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_groupsKey) reads the groups again, after a change.
export const _groupsKey = 'app:pihole-groups';

type Data = {
	groups: PiholeGroup[];
	error: string | null;
	allowed: boolean;
	primaryDown?: boolean;
	drifted?: boolean;
};

// Reading a target's Pi-hole groups needs any permission on it, so anyone who can use the target sees this page;
// changing them needs piholegroups.edit, which the page checks for its buttons.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_groupsKey);
	const { target } = await parent();
	if (!target || !canAny(target)) return { groups: [], error: null, allowed: false };
	try {
		const list = await unwrap(api.GET('/api/v1/targets/{target}/groups', { params: { path: { target } }, fetch }));
		return { groups: list.groups, error: null, allowed: true, drifted: list.drifted };
	} catch (e) {
		if (e instanceof ApiError) return { groups: [], error: e.message, allowed: true, primaryDown: e.details.primary === true };
		throw e;
	}
};
