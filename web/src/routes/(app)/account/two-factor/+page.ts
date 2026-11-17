// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { TOTPStatus } from '#lib/totp.js';
import type { PageLoad } from './$types';

export const _totpKey = 'app:totp';

// Your own two-factor login: anyone may set theirs up, so there is no permission to check. It is also the one page a
// session held to setting it up can reach (see the app layout).
export const load: PageLoad = async ({ fetch, depends }): Promise<{ status: TOTPStatus | null; error: string | null }> => {
	// depends() names this load, so invalidate(_totpKey) runs it again after a change, without a full navigation.
	depends(_totpKey);
	try {
		return { status: await unwrap(api.GET('/api/v1/auth/totp', { fetch })), error: null };
	} catch (e) {
		if (e instanceof ApiError) return { status: null, error: e.message };
		throw e;
	}
};
