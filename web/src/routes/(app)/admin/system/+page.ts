// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { can, canAnyGlobal } from '#lib/permissions.js';
import type { SecretStatus, UpdateStatus, VersionInfo } from '#lib/system.js';
import type { PageLoad } from './$types';

// invalidate(_systemKey) makes SvelteKit run this load again, after a reload or restart.
export const _systemKey = 'app:system';

// Each part loads on its own, so one failing (or not being allowed) doesn't hide the others. null: not allowed.
type Part<T> = { value: T | null; error: string | null } | null;

type Data = {
	allowed: boolean;
	version: Part<VersionInfo>;
	update: Part<UpdateStatus>;
	secrets: Part<SecretStatus[]>;
};

async function part<T>(call: () => Promise<T>): Promise<{ value: T | null; error: string | null }> {
	try {
		return { value: await call(), error: null };
	} catch (e) {
		if (e instanceof ApiError) return { value: null, error: e.message };
		throw e;
	}
}

// The version (any session), the update status (app.update) and the secrets (config.reload), read in parallel.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_systemKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!canAnyGlobal('config.reload', 'app.update')) {
		return { allowed: false, version: null, update: null, secrets: null };
	}
	const [version, update, secrets] = await Promise.all([
		part(() => unwrap(api.GET('/api/v1/system/version', { fetch }))),
		can('app.update') ? part(() => unwrap(api.GET('/api/v1/system/update', { fetch }))) : null,
		can('config.reload')
			? part(async () => (await unwrap(api.GET('/api/v1/system/secrets', { fetch }))).secrets)
			: null
	]);
	return { allowed: true, version, update, secrets };
};
