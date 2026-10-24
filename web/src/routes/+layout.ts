// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { redirect } from '@sveltejs/kit';
import { getAbout, type About } from '#lib/api/about.js';
import { session } from '#lib/stores/session.svelte.js';
import type { LayoutLoad } from './$types';

// Page options for every route (they cascade from the root layout).
// ssr = false: render only in the browser; the Go binary has no JS runtime.
// prerender = false: nothing is built ahead of time; adapter-static's
// fallback page (index.html) boots the app for every URL.
export const ssr = false;
export const prerender = false;

// Asked once per page load: this load runs again on every navigation (it reads `url`), and the source link and the
// session don't change in between.
let about: Promise<About> | null = null;

// SvelteKit convention: a `load` exported from +layout.ts runs before the layout renders, and whatever it returns arrives in the layout (and every page under it) as the `data` prop. Because this one reads `url`, SvelteKit runs it again on every navigation, which is what lets it send the browser to /setup or away from it.
export const load: LayoutLoad = async ({ fetch, url }) => {
	about ??= getAbout(fetch);
	let unavailable = false;
	try {
		await session.init(fetch);
	} catch {
		// The API didn't answer, or answered with something unexpected. The layout says so instead of rendering a page
		// that would only fail.
		unavailable = true;
	}

	if (!unavailable) {
		// redirect() throws: SvelteKit catches it and navigates instead of rendering this route.
		if (session.status === 'setup' && url.pathname !== '/setup') redirect(307, '/setup');
		if (session.status !== 'setup' && url.pathname === '/setup') {
			redirect(307, session.status === 'authenticated' ? '/' : '/login');
		}
	}
	return { about: await about, unavailable };
};
