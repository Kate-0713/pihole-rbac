// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { Role } from '#lib/roles.js';
import type { User } from '#lib/users.js';
import type { PageLoad } from './$types';

// invalidate(_usersKey) reads the users and roles again, after a change.
export const _usersKey = 'app:users';

type Data = { users: User[]; roles: Role[]; error: string | null; allowed: boolean };

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_usersKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('users.manage')) return { users: [], roles: [], error: null, allowed: false };
	try {
		// GET /roles is readable with users.manage, so the role checklists can say which roles may be given.
		const [users, roles] = await Promise.all([
			unwrap(api.GET('/api/v1/users', { fetch })),
			unwrap(api.GET('/api/v1/roles', { fetch }))
		]);
		return { users: users.users, roles: roles.roles, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { users: [], roles: [], error: e.message, allowed: true };
		throw e;
	}
};
