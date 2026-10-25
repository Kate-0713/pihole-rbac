// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap, type Schemas } from '#lib/api/client.js';
import type { PiholeGroup } from '#lib/pihole.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

export type PiholeClient = Schemas['PiholeClient'];

// invalidate(_clientsKey) reads the clients again, after a change.
export const _clientsKey = 'app:clients';

type Data = { clients: PiholeClient[]; groups: PiholeGroup[]; error: string | null; allowed: boolean; primaryDown?: boolean };

// The same shape as the domains page: the clients and the Pi-hole's groups in parallel, nothing asked without
// clients.view, and a Pi-hole that is down shown on the page.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_clientsKey);
	const { target } = await parent();
	const empty = { clients: [], groups: [] };
	if (!target || !can('clients.view', target)) return { ...empty, error: null, allowed: false };

	const params = { params: { path: { target } }, fetch };
	try {
		const [list, groups] = await Promise.all([
			unwrap(api.GET('/api/v1/targets/{target}/clients', params)),
			unwrap(api.GET('/api/v1/targets/{target}/groups', params))
		]);
		return { clients: list.clients, groups: groups.groups, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { ...empty, error: e.message, allowed: true, primaryDown: e.details.primary === true };
		throw e;
	}
};
