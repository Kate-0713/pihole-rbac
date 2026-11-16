// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap, type Schemas } from '#lib/api/client.js';
import type { PiholeGroup } from '#lib/pihole.js';
import { can } from '#lib/permissions.js';
import type { TempChangeList } from '#lib/temp-changes.js';
import type { PageLoad } from './$types';

export type PiholeClient = Schemas['PiholeClient'];

// invalidate(_clientsKey) reads the clients again, after a change.
export const _clientsKey = 'app:clients';

type Data = { clients: PiholeClient[]; groups: PiholeGroup[]; changes: TempChangeList | null; error: string | null; allowed: boolean; primaryDown?: boolean; drifted?: boolean };

// The same shape as the domains page: the clients and the Pi-hole's groups in parallel, nothing asked without
// clients.view, and a Pi-hole that is down shown on the page.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_clientsKey);
	const { target } = await parent();
	const empty = { clients: [], groups: [], changes: null };
	if (!target || !can('clients.view', target)) return { ...empty, error: null, allowed: false };

	const params = { params: { path: { target } }, fetch };
	try {
		// The temporary changes come from the app's own database, so a failure here only leaves them out (and with them
		// the "Change temporarily" action, which needs the limits that come in the same answer).
		const [list, groups, changes] = await Promise.all([
			unwrap(api.GET('/api/v1/targets/{target}/clients', params)),
			unwrap(api.GET('/api/v1/targets/{target}/groups', params)),
			unwrap(api.GET('/api/v1/targets/{target}/clients/temporary', params)).catch((): TempChangeList | null => null)
		]);
		return { clients: list.clients, groups: groups.groups, changes, error: null, allowed: true, drifted: list.drifted };
	} catch (e) {
		if (e instanceof ApiError) return { ...empty, error: e.message, allowed: true, primaryDown: e.details.primary === true };
		throw e;
	}
};
