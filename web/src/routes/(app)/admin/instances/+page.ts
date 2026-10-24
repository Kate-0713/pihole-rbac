// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { Instance } from '#lib/instances.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_instancesKey) reads the list again, after a change.
export const _instancesKey = 'app:instances';

type Data = { instances: Instance[]; error: string | null; allowed: boolean };

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_instancesKey);
	// SvelteKit runs a page's load alongside its layouts' loads unless it awaits parent(). Waiting means the session,
	// which can() reads, is known even on a full page load.
	await parent();
	// The server would refuse with a 403; asking first gives a plainer message and saves the request.
	if (!can('instances.manage')) return { instances: [], error: null, allowed: false };
	try {
		const { instances } = await unwrap(api.GET('/api/v1/instances', { fetch }));
		return { instances, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { instances: [], error: e.message, allowed: true };
		throw e;
	}
};
