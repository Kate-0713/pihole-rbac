// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { error } from '@sveltejs/kit';
import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { Catalogue, Role } from '#lib/roles.js';
import type { PageLoad } from './$types';

type Data = { role: Role | null; catalogue: Catalogue | null; error: string | null; allowed: boolean };

// params.id is the [id=integer] part of the URL, already parsed to a number by the matcher in src/params.ts.
export const load: PageLoad = async ({ params, parent, fetch }): Promise<Data> => {
	await parent();
	if (!can('roles.manage')) return { role: null, catalogue: null, error: null, allowed: false };
	const id = params.id;
	try {
		const [role, catalogue] = await Promise.all([
			unwrap(api.GET('/api/v1/roles/{id}', { params: { path: { id } }, fetch })),
			unwrap(api.GET('/api/v1/roles/catalogue', { fetch }))
		]);
		return { role, catalogue, error: null, allowed: true };
	} catch (e) {
		// SvelteKit's error() ends the load and renders the nearest +error.svelte: here the root one, the same
		// "page doesn't exist" page as for any unknown URL.
		if (e instanceof ApiError && e.code === 'not_found') error(404, 'There is no such role.');
		if (e instanceof ApiError) return { role: null, catalogue: null, error: e.message, allowed: true };
		throw e;
	}
};
