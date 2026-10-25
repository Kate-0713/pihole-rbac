// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { Group } from '#lib/groups.js';
import type { Instance } from '#lib/instances.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_groupsKey) reads the groups and instances again, after a change.
export const _groupsKey = 'app:instance-groups';

type Data = { groups: Group[]; instances: Instance[]; error: string | null; allowed: boolean };

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_groupsKey);
	// Await the layouts first, so the session can() reads is known even on a full page load.
	await parent();
	if (!can('instances.manage')) return { groups: [], instances: [], error: null, allowed: false };
	try {
		// The instances name the members and fill the form's checklist; both lists are read at once.
		const [groups, instances] = await Promise.all([
			unwrap(api.GET('/api/v1/instance-groups', { fetch })),
			unwrap(api.GET('/api/v1/instances', { fetch }))
		]);
		return { groups: groups.groups, instances: instances.instances, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { groups: [], instances: [], error: e.message, allowed: true };
		throw e;
	}
};
