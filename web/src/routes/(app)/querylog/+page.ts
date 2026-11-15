// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap, type Schemas } from '#lib/api/client.js';
import { can } from '#lib/permissions.js';
import {
	apiQuery,
	forgetSnapshot,
	readFilters,
	rememberSnapshot,
	searchKey,
	snapshotFor,
	type QueryFilters
} from '#lib/queries.js';
import type { PageLoad } from './$types';

// invalidate(_queriesKey) reads the log again, for the Refresh button (which forgets the snapshot first).
export const _queriesKey = 'app:queries';

type Data = {
	filters: QueryFilters;
	error: string | null;
	allowed: boolean;
	// The page read, or null when it couldn't be (error says why) or isn't allowed.
	log: Schemas['QueryLog'] | null;
};

// The filters and the page live in the URL, so a page can be bookmarked or shared, and Back undoes a step. Reading
// url.searchParams here tells SvelteKit to run load again whenever the query string changes, which is what applying
// a filter or turning a page does. The snapshot is kept in memory instead (see snapshotFor): a later page of the same
// search sends it, so it shows the same entries however many queries have arrived since.
export const load: PageLoad = async ({ parent, fetch, depends, url }): Promise<Data> => {
	depends(_queriesKey);
	const filters = readFilters(url.searchParams);
	const { target } = await parent();
	if (!target || !can('querylog.view', target)) return { filters, error: null, allowed: false, log: null };

	const key = searchKey(target, filters);
	const read = (snapshot?: string) => {
		const query = apiQuery(filters);
		if (snapshot) query.snapshot = snapshot;
		return unwrap(api.GET('/api/v1/targets/{target}/queries', { params: { path: { target }, query }, fetch }));
	};
	try {
		const snapshot = snapshotFor(key);
		let log;
		try {
			log = await read(snapshot);
		} catch (e) {
			// A snapshot the server won't take (one from an older version, say) only costs the page its stability:
			// read the page afresh rather than show an error.
			if (!snapshot || !(e instanceof ApiError) || e.details.field !== 'snapshot') throw e;
			forgetSnapshot();
			log = await read();
		}
		rememberSnapshot(key, log.snapshot);
		return { filters, error: null, allowed: true, log };
	} catch (e) {
		if (e instanceof ApiError) return { filters, error: e.message, allowed: true, log: null };
		throw e;
	}
};
