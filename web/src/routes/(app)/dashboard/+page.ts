// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { RunList } from '#lib/clientreset.js';
import type { ScheduleStatus } from '#lib/schedules.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// The key this load depends on. invalidate(_summaryKey) runs it again without reloading the page: that's how the
// dashboard refreshes every few seconds, and after a change. SvelteKit convention: a +page.ts may only export its
// own names (load, ssr and so on) plus names starting with an underscore, which it leaves alone.
export const _summaryKey = 'app:dashboard-summary';

// SvelteKit convention: a page's load runs before the page renders and again whenever what it read changes. It
// reads the target from the (app) layout through parent(), so picking another instance runs it again.
export const load: PageLoad = async ({ parent, fetch, depends }) => {
	depends(_summaryKey);
	const { target } = await parent();
	if (!target) return { summary: null, error: null, resets: null, schedules: null, fetchedAt: Date.now() };

	// The client reset card's data, read alongside the summary for someone who may run it there: the target's newest
	// run and how many rules it has. It's a database read, so it doesn't wait on the Pi-holes, and a failure only
	// leaves the card out.
	const resets = can('clientreset.run', target)
		? unwrap(api.GET('/api/v1/targets/{target}/client-reset/runs', { params: { path: { target }, query: { limit: 1 } }, fetch })).catch(
				(): RunList | null => null
			)
		: Promise.resolve(null);
	// What the target's schedules are doing, for the schedules line and the blocking card: from the app's database too,
	// and readable with any permission on the target. A failure only leaves the line out.
	const schedules = unwrap(api.GET('/api/v1/targets/{target}/schedules/status', { params: { path: { target } }, fetch })).catch(
		(): ScheduleStatus | null => null
	);

	try {
		const summary = await unwrap(api.GET('/api/v1/targets/{target}/summary', { params: { path: { target } }, fetch }));
		return { summary, error: null, resets: await resets, schedules: await schedules, fetchedAt: Date.now() };
	} catch (e) {
		// A Pi-hole that is down is something to show on the page, not a reason to replace the page with an error:
		// the next refresh may well succeed. A session that has ended is handled by the API client, which sends the
		// user to log in.
		if (e instanceof ApiError) {
			return { summary: null, error: e.message, resets: await resets, schedules: await schedules, fetchedAt: Date.now() };
		}
		throw e;
	}
};
