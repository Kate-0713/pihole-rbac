// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { redirect } from '@sveltejs/kit';
import { loginURL, session } from '#lib/stores/session.svelte.js';
import type { LayoutLoad } from './$types';

// SvelteKit convention: a folder in (parentheses) is a route group. It adds a layout to the pages inside it without
// adding anything to their URLs, so (app)/+page.svelte is still "/". Every page that needs a session lives here.
//
// This only decides what to render. The server refuses every API request without a session whatever the UI does.
export const load: LayoutLoad = async ({ parent, url }) => {
	await parent(); // the root layout's load has asked the server about the session by now
	if (session.status !== 'authenticated') redirect(307, loginURL(url.pathname + url.search));
	return {};
};
