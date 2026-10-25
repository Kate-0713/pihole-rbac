// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import { apiQuery, readAuditFilters, type AuditFilters, type AuditList } from '#lib/audit.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

export const _auditKey = 'app:audit';

type Data = { list: AuditList | null; filters: AuditFilters; error: string | null; allowed: boolean };

// The first page of entries matching the filters in the URL. Reading url.searchParams makes SvelteKit run load again
// whenever the query string changes, which is what applying a filter does; "Show more" reads the next pages on the
// page itself.
export const load: PageLoad = async ({ parent, fetch, depends, url }): Promise<Data> => {
	depends(_auditKey);
	const filters = readAuditFilters(url.searchParams);
	await parent(); // the session must be known before can() is asked (see the instances page)
	if (!can('audit.view')) return { list: null, filters, error: null, allowed: false };
	try {
		const list = await unwrap(api.GET('/api/v1/audit', { params: { query: apiQuery(filters) }, fetch }));
		return { list, filters, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { list: null, filters, error: e.message, allowed: true };
		throw e;
	}
};
