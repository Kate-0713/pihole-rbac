// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAbout } from '#lib/api/about.js';
import type { LayoutLoad } from './$types';

// Page options for every route (they cascade from the root layout).
// ssr = false: render only in the browser; the Go binary has no JS runtime.
// prerender = false: nothing is built ahead of time; adapter-static's
// fallback page (index.html) boots the app for every URL.
export const ssr = false;
export const prerender = false;

// SvelteKit convention: a `load` exported from +layout.ts runs before the layout renders, and whatever it returns arrives in the layout (and every page under it) as the `data` prop. The root layout's load runs once on startup and isn't re-run on client-side navigation unless something it depends on changes.
export const load: LayoutLoad = async ({ fetch }) => {
	return { about: await getAbout(fetch) };
};
