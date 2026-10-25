// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { RunList, Rules } from '#lib/clientreset.js';
import { can } from '#lib/permissions.js';
import type { GeneralSettings } from '#lib/sessions.js';
import type { PageLoad } from './$types';

// invalidate(_resetKey) makes SvelteKit run this load again: after a save, and for Refresh.
export const _resetKey = 'app:client-reset';

type Data = {
	rules: Rules | null;
	general: GeneralSettings | null;
	runs: RunList | null;
	error: string | null;
	allowed: boolean;
};

// The rules, the general settings (for the schedule) and the newest page of every target's runs, read in parallel.
// All three need settings.manage.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_resetKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	const none = { rules: null, general: null, runs: null };
	if (!can('settings.manage')) return { ...none, error: null, allowed: false };
	try {
		const [rules, general, runs] = await Promise.all([
			unwrap(api.GET('/api/v1/client-reset/rules', { fetch })),
			unwrap(api.GET('/api/v1/settings/general', { fetch })),
			unwrap(api.GET('/api/v1/client-reset/runs', { fetch }))
		]);
		return { rules, general, runs, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { ...none, error: e.message, allowed: true };
		throw e;
	}
};
