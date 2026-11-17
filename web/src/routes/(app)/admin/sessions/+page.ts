// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { Catalogue } from '#lib/roles.js';
import type { SessionList } from '#lib/sessions.js';
import type { APIToken } from '#lib/tokens.js';
import type { PageLoad } from './$types';

export const _sessionsKey = 'app:sessions';

type Data = {
	list: SessionList | null;
	tokens: APIToken[] | null;
	catalogue: Catalogue | null; // names the instances and groups in tokens' grants; only with roles.manage
	error: string | null;
	allowed: boolean;
};

// Everyone's sessions and API tokens, for sessions.manage: a token is effectively a long session. Your own are under
// /account/sessions and /account/tokens, for everyone.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_sessionsKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('sessions.manage')) return { list: null, tokens: null, catalogue: null, error: null, allowed: false };
	try {
		const [list, tokens, catalogue] = await Promise.all([
			unwrap(api.GET('/api/v1/sessions', { fetch })),
			unwrap(api.GET('/api/v1/tokens', { fetch })),
			can('roles.manage') ? unwrap(api.GET('/api/v1/roles/catalogue', { fetch })) : Promise.resolve(null)
		]);
		return { list, tokens: tokens.tokens, catalogue, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { list: null, tokens: null, catalogue: null, error: e.message, allowed: true };
		throw e;
	}
};
