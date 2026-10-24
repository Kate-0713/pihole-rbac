// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { Catalogue, Role } from '#lib/roles.js';
import type { PageLoad } from './$types';

export const _rolesKey = 'app:roles';

type Data = { roles: Role[]; catalogue: Catalogue | null; error: string | null; allowed: boolean };

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_rolesKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('roles.manage')) return { roles: [], catalogue: null, error: null, allowed: false };
	try {
		const [list, catalogue] = await Promise.all([
			unwrap(api.GET('/api/v1/roles', { fetch })),
			unwrap(api.GET('/api/v1/roles/catalogue', { fetch }))
		]);
		return { roles: list.roles, catalogue, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { roles: [], catalogue: null, error: e.message, allowed: true };
		throw e;
	}
};
