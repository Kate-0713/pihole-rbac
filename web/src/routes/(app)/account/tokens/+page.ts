// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import type { APIToken, TokenGrantable } from '#lib/tokens.js';
import type { PageLoad } from './$types';

export const _myTokensKey = 'app:my-tokens';

type Data = {
	tokens: APIToken[] | null;
	grantable: TokenGrantable | null; // null without tokens.use: the page lists and revokes, but can't make one
	totpOn: boolean;
	error: string | null;
};

// Your own API tokens. Anyone may list and revoke theirs, so someone who has lost tokens.use can still clean up; making
// one needs tokens.use, and what a token can hold, and whether a code will be asked for, are only read then.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_myTokensKey);
	await parent(); // the session must be known before can() is asked
	const canMake = can('tokens.use');
	try {
		// Promise.all runs the three reads at once rather than one after another.
		const [list, grantable, totp] = await Promise.all([
			unwrap(api.GET('/api/v1/account/tokens', { fetch })),
			canMake ? unwrap(api.GET('/api/v1/account/tokens/grantable', { fetch })) : Promise.resolve(null),
			canMake ? unwrap(api.GET('/api/v1/auth/totp', { fetch })) : Promise.resolve(null)
		]);
		return { tokens: list.tokens, grantable, totpOn: totp?.enabled ?? false, error: null };
	} catch (e) {
		if (e instanceof ApiError) return { tokens: null, grantable: null, totpOn: false, error: e.message };
		throw e;
	}
};
