// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { LogDestination } from '#lib/logdestinations.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_destinationsKey) reads the list again, after a change.
export const _destinationsKey = 'app:log-destinations';

type Data = { destinations: LogDestination[]; error: string | null; allowed: boolean };

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_destinationsKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('logging.manage')) return { destinations: [], error: null, allowed: false };
	try {
		const list = await unwrap(api.GET('/api/v1/settings/log-destinations', { fetch }));
		return { destinations: list.destinations, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { destinations: [], error: e.message, allowed: true };
		throw e;
	}
};
