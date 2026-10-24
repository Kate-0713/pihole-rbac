// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { Catalogue } from '#lib/roles.js';
import type { PageLoad } from './$types';

// SvelteKit picks this folder over [id=integer] for /admin/roles/new: a route without parameters always wins over one
// with, and "new" wouldn't pass the integer matcher anyway.
export const load: PageLoad = async ({ parent, fetch }): Promise<{ catalogue: Catalogue | null; error: string | null; allowed: boolean }> => {
	await parent();
	if (!can('roles.manage')) return { catalogue: null, error: null, allowed: false };
	try {
		return { catalogue: await unwrap(api.GET('/api/v1/roles/catalogue', { fetch })), error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { catalogue: null, error: e.message, allowed: true };
		throw e;
	}
};
