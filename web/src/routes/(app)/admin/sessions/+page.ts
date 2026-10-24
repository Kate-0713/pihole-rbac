// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { SessionList } from '#lib/sessions.js';
import type { PageLoad } from './$types';

export const _sessionsKey = 'app:sessions';

type Data = { list: SessionList | null; error: string | null; allowed: boolean };

// Everyone's sessions, for sessions.manage. Your own are under /account/sessions, for everyone.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_sessionsKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('sessions.manage')) return { list: null, error: null, allowed: false };
	try {
		return { list: await unwrap(api.GET('/api/v1/sessions', { fetch })), error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { list: null, error: e.message, allowed: true };
		throw e;
	}
};
