// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { redirect } from '@sveltejs/kit';
import { safeNext, session } from '#lib/stores/session.svelte.js';
import type { PageLoad } from './$types';

// Someone already logged in has no use for the login page.
export const load: PageLoad = async ({ parent, url }) => {
	await parent();
	if (session.status === 'authenticated') redirect(307, safeNext(url.searchParams.get('next')));
	return {};
};
