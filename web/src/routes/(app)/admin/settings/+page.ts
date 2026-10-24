// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { GeneralSettings } from '#lib/sessions.js';
import type { PageLoad } from './$types';

export const _settingsKey = 'app:settings';

type Data = { general: GeneralSettings | null; error: string | null; allowed: boolean };

// The general settings. Audit retention and the client-reset schedule join them in later milestones.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_settingsKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('settings.manage')) return { general: null, error: null, allowed: false };
	try {
		return { general: await unwrap(api.GET('/api/v1/settings/general', { fetch })), error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { general: null, error: e.message, allowed: true };
		throw e;
	}
};
