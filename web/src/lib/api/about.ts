// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { api, type Schemas } from './client.js';

export type About = Schemas['About'];

// Used only if the API can't be reached (e.g. `npm run dev` without the Go server), so the source link is never missing. The running binary's own value always wins.
export const fallbackAbout: About = {
	source_url: 'https://github.com/Kate-0713/pihole-rbac',
	license: 'AGPL-3.0-or-later'
};

// Takes SvelteKit's `fetch` (passed into load functions) rather than the global one, so requests made during navigation are tracked by the framework. openapi-fetch accepts it per request.
export async function getAbout(fetch: typeof globalThis.fetch): Promise<About> {
	try {
		const { data } = await api.GET('/api/v1/about', { fetch });
		// The types say what the spec promises; this check covers a response that isn't from our API at all (a dev proxy error page, say).
		if (typeof data?.source_url !== 'string' || typeof data.license !== 'string') return fallbackAbout;
		return { source_url: data.source_url, license: data.license };
	} catch {
		return fallbackAbout;
	}
}
