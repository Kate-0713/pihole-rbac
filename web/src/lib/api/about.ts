// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Response of GET /api/v1/about (schema About in api/openapi.yaml). Hand-written until openapi-typescript generates the API types.
export type About = {
	source_url: string;
	license: string;
};

// Used only if the API can't be reached (e.g. `npm run dev` without the Go server), so the source link is never missing. The running binary's own value always wins.
export const fallbackAbout: About = {
	source_url: 'https://github.com/Kate-0713/pihole-rbac',
	license: 'AGPL-3.0-or-later'
};

// Takes SvelteKit's `fetch` (passed into load functions) rather than the global one, so requests made during navigation are tracked by the framework.
export async function getAbout(fetch: typeof globalThis.fetch): Promise<About> {
	try {
		const res = await fetch('/api/v1/about');
		if (!res.ok) return fallbackAbout;
		const body = (await res.json()) as Partial<About>;
		if (typeof body.source_url !== 'string' || typeof body.license !== 'string') return fallbackAbout;
		return { source_url: body.source_url, license: body.license };
	} catch {
		return fallbackAbout;
	}
}
