// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap, type Schemas } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_dhcpKey) reads the DHCP data again, after a change.
export const _dhcpKey = 'app:dhcp';

type Data = {
	settings: Schemas['DHCPSettingsRead'] | null;
	leases: Schemas['DHCPLeases'] | null;
	statics: Schemas['DHCPStaticLeases'] | null;
	error: string | null;
	allowed: boolean;
};

const none = { settings: null, leases: null, statics: null };

// The three reads run together. Load functions run in the browser here (the app is an SPA with SSR off); parent() is
// the layout's data, which says which target is selected; depends() names this data so invalidate() can refresh it.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_dhcpKey);
	const { target } = await parent();
	if (!target || !can('dhcp.view', target)) return { ...none, error: null, allowed: false };
	const params = { params: { path: { target } }, fetch };
	try {
		const [settings, leases, statics] = await Promise.all([
			unwrap(api.GET('/api/v1/targets/{target}/dhcp', params)),
			unwrap(api.GET('/api/v1/targets/{target}/dhcp/leases', params)),
			unwrap(api.GET('/api/v1/targets/{target}/dhcp/static-leases', params))
		]);
		return { settings, leases, statics, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { ...none, error: e.message, allowed: true };
		throw e;
	}
};
