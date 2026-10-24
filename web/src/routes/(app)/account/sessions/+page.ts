// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { SessionList } from '#lib/sessions.js';
import type { PageLoad } from './$types';

export const _mySessionsKey = 'app:my-sessions';

// Your own sessions: everyone may see and end these, so there is no permission to check.
export const load: PageLoad = async ({ fetch, depends }): Promise<{ list: SessionList | null; error: string | null }> => {
	depends(_mySessionsKey);
	try {
		const list = await unwrap(api.GET('/api/v1/sessions', { fetch, params: { query: { mine: true } } }));
		return { list, error: null };
	} catch (e) {
		if (e instanceof ApiError) return { list: null, error: e.message };
		throw e;
	}
};
