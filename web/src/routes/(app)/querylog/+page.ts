// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap, type Schemas } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import { readFilters, type QueryFilters, type QueryLogEntry } from '#lib/queries.js';
import type { PageLoad } from './$types';

// invalidate(_queriesKey) reads the log again, for the Refresh button.
export const _queriesKey = 'app:queries';

// members is set for a mirrored group: how each member answered, so the page can say which are missing.
type Data = {
	queries: QueryLogEntry[];
	filters: QueryFilters;
	error: string | null;
	allowed: boolean;
	members?: Schemas['MemberRead'][];
};

// The filters live in the URL, so a filtered view can be bookmarked or shared, and Back undoes a filter. Reading
// url.searchParams here tells SvelteKit to run load again whenever the query string changes, which is what
// applying a filter does.
export const load: PageLoad = async ({ parent, fetch, depends, url }): Promise<Data> => {
	depends(_queriesKey);
	const filters = readFilters(url.searchParams);
	const { target } = await parent();
	if (!target || !can('querylog.view', target)) return { queries: [], filters, error: null, allowed: false };

	const query: { length: number; domain?: string; client?: string } = { length: filters.length };
	if (filters.domain) query.domain = filters.domain;
	if (filters.client) query.client = filters.client;
	try {
		const log = await unwrap(api.GET('/api/v1/targets/{target}/queries', { params: { path: { target }, query }, fetch }));
		return { queries: log.queries, filters, error: null, allowed: true, members: log.members };
	} catch (e) {
		if (e instanceof ApiError) return { queries: [], filters, error: e.message, allowed: true };
		throw e;
	}
};
