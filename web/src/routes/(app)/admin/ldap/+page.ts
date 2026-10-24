// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { LDAPView, Mapping, Method } from '#lib/ldap.js';
import { can } from '#lib/permissions.js';
import type { Role } from '#lib/roles.js';
import type { PageLoad } from './$types';

// invalidate(_ldapKey) reads everything on the page again, after a change.
export const _ldapKey = 'app:ldap';

// The page has two halves with their own permissions: the login methods and LDAP server need settings.manage, the
// group mappings and the test tool need roles.manage. Each half is read only with its permission.
type Data = {
	settings: { methods: Method[]; ldap: LDAPView } | null;
	mappings: { roles: Role[]; mappings: Mapping[] } | null;
	error: string | null;
	allowed: boolean;
};

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_ldapKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	const canSettings = can('settings.manage');
	const canRoles = can('roles.manage');
	if (!canSettings && !canRoles) return { settings: null, mappings: null, error: null, allowed: false };
	try {
		const [settings, mappings] = await Promise.all([
			canSettings ? loadSettings(fetch) : null,
			canRoles ? loadMappings(fetch) : null
		]);
		return { settings, mappings, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { settings: null, mappings: null, error: e.message, allowed: true };
		throw e;
	}
};

async function loadSettings(fetch: typeof globalThis.fetch) {
	const [auth, ldap] = await Promise.all([
		unwrap(api.GET('/api/v1/settings/auth', { fetch })),
		unwrap(api.GET('/api/v1/settings/ldap', { fetch }))
	]);
	return { methods: auth.methods, ldap };
}

// Mappings are listed per role; only roles that have any are asked, and in parallel. An install has a handful.
async function loadMappings(fetch: typeof globalThis.fetch) {
	const { roles } = await unwrap(api.GET('/api/v1/roles', { fetch }));
	const lists = await Promise.all(
		roles
			.filter((r) => r.ldap_groups.length > 0)
			.map((r) => unwrap(api.GET('/api/v1/roles/{id}/ldap-groups', { fetch, params: { path: { id: r.id } } })))
	);
	return { roles, mappings: lists.flatMap((l) => l.mappings) };
}
