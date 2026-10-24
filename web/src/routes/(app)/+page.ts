// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { redirect } from '@sveltejs/kit';
import { withTarget } from '#lib/stores/targets.svelte.js';
import type { PageLoad } from './$types';

// "/" has no page of its own: it opens the dashboard for the selected target.
export const load: PageLoad = async ({ parent }) => {
	const { target } = await parent();
	redirect(307, withTarget('/dashboard', target));
};
