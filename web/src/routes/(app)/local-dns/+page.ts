// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { LocalDNS } from '#lib/local-dns.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_localDNSKey) reads the records again, after a change.
export const _localDNSKey = 'app:local-dns';

type Data = {
	dns: LocalDNS | null;
	error: string | null;
	allowed: boolean;
	primaryDown?: boolean;
};

// A load function runs before the page renders, in the browser here (the app is an SPA with SSR off). parent() is
// the layout's data, which says which target is selected; depends() names this data so invalidate() can refresh it.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_localDNSKey);
	const { target } = await parent();
	if (!target || !can('localdns.view', target)) return { dns: null, error: null, allowed: false };
	try {
		const dns = await unwrap(api.GET('/api/v1/targets/{target}/local-dns', { params: { path: { target } }, fetch }));
		return { dns, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { dns: null, error: e.message, allowed: true, primaryDown: e.details.primary === true };
		throw e;
	}
};
