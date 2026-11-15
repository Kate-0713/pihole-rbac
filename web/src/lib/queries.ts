// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Schemas } from '#lib/api/client.js';

export type QueryLogEntry = Schemas['QueryLogEntry'];
export type QueryStatus = Schemas['QueryStatus'];
export type QueryType = Schemas['QueryType'];
export type QueryResult = 'blocked' | 'allowed' | 'cached';

// The page sizes the server takes, and its default; the longest filter text it takes.
export const pageSizes = [25, 50, 100, 250] as const;
export type PageSize = (typeof pageSizes)[number];
export const defaultPageSize: PageSize = 100;
export const maxFilterChars = 255;
// How deep a mirrored group's merged log can be paged (the server's limit, for the wording).
export const mergedDepth = 5000;

// The time ranges offered. A preset is kept in the URL by name, so a bookmark of "the last hour" stays relative;
// custom keeps its from and until.
export const timeRanges = {
	'': 'Any time',
	'1h': 'Last hour',
	'24h': 'Last 24 hours',
	'7d': 'Last 7 days',
	'30d': 'Last 30 days',
	custom: 'Custom range'
} as const;
export type TimeRange = keyof typeof timeRanges;
const rangeMs: Record<string, number> = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };

export const queryTypes: QueryType[] = [
	'A', 'AAAA', 'ANY', 'SRV', 'SOA', 'PTR', 'TXT', 'NAPTR', 'MX', 'DS', 'RRSIG', 'DNSKEY', 'NS', 'SVCB', 'HTTPS', 'OTHER'
];
export const queryResults: Record<QueryResult, string> = { blocked: 'Blocked', allowed: 'Allowed', cached: 'Cached' };

export type QueryFilters = {
	domain: string;
	client: string;
	range: TimeRange;
	from: string; // ISO date-times, only for a custom range; '' when not set
	until: string;
	status: QueryStatus | '';
	type: QueryType | '';
	result: QueryResult | '';
	page: number;
	pageSize: PageSize;
	member: number | null; // a mirrored group's member, by instance ID
};

export const noFilters: QueryFilters = {
	domain: '',
	client: '',
	range: '',
	from: '',
	until: '',
	status: '',
	type: '',
	result: '',
	page: 1,
	pageSize: defaultPageSize,
	member: null
};

// The characters the server takes in a domain or client filter (a client may also hold ':').
const searchText = /^[A-Za-z0-9._*-]*$/;
const clientText = /^[A-Za-z0-9._*:-]*$/;

// filterProblem says what is wrong with a domain or client filter the server would refuse, or null.
export function filterProblem(field: 'domain' | 'client', value: string): string | null {
	const v = value.trim();
	if (v.length > maxFilterChars) return `Up to ${maxFilterChars} characters.`;
	if (!(field === 'client' ? clientText : searchText).test(v)) {
		return field === 'client'
			? 'Letters, digits, dots, colons, hyphens, underscores and * only.'
			: 'Letters, digits, dots, hyphens, underscores and * only.';
	}
	return null;
}

const isoTime = (v: string | null): string => {
	if (!v) return '';
	const t = Date.parse(v);
	return Number.isNaN(t) ? '' : new Date(t).toISOString();
};
const wholeNumber = (v: string | null): number => (v !== null && /^\d+$/.test(v) ? Number(v) : NaN);

// readFilters reads the filters from a URL's query string. Anything the server would refuse is dropped rather than
// failing the page, since the URL can be typed by hand.
export function readFilters(params: URLSearchParams): QueryFilters {
	const text = (key: 'domain' | 'client') => {
		const v = (params.get(key) ?? '').trim();
		return filterProblem(key, v) === null ? v : '';
	};
	const range = params.get('range') ?? '';
	const status = params.get('status') ?? '';
	const type = params.get('type') ?? '';
	const result = params.get('result') ?? '';
	const page = wholeNumber(params.get('page'));
	const size = wholeNumber(params.get('page_size'));
	const member = wholeNumber(params.get('member'));
	const f: QueryFilters = {
		...noFilters,
		domain: text('domain'),
		client: text('client'),
		range: Object.hasOwn(timeRanges, range) ? (range as TimeRange) : '',
		status: Object.hasOwn(statuses, status) ? (status as QueryStatus) : '',
		type: (queryTypes as string[]).includes(type) ? (type as QueryType) : '',
		result: Object.hasOwn(queryResults, result) ? (result as QueryResult) : '',
		page: page >= 1 && page <= 1_000_000 ? page : 1,
		pageSize: (pageSizes as readonly number[]).includes(size) ? (size as PageSize) : defaultPageSize,
		member: member >= 1 ? member : null
	};
	if (f.range === 'custom') {
		f.from = isoTime(params.get('from'));
		f.until = isoTime(params.get('until'));
		if (f.from && f.until && Date.parse(f.until) <= Date.parse(f.from)) f.until = '';
		if (!f.from && !f.until) f.range = '';
	}
	return f;
}

// filterURL returns the path and query string for `url` with the filters changed. Other parameters (the target) are
// kept, and empty or default values are left out so the URL stays short. Changing anything but the page starts again
// at page 1. It takes anything with an href, because SvelteKit's page.url is a read-only URL; a copy is changed.
export function filterURL(url: { readonly href: string }, changes: Partial<QueryFilters>): string {
	const next = new URL(url.href);
	const all = { ...changes };
	if (!('page' in changes)) all.page = 1;
	if ('range' in changes && changes.range !== 'custom') {
		all.from = '';
		all.until = '';
	}
	const keys: Record<keyof QueryFilters, string> = {
		domain: 'domain',
		client: 'client',
		range: 'range',
		from: 'from',
		until: 'until',
		status: 'status',
		type: 'type',
		result: 'result',
		page: 'page',
		pageSize: 'page_size',
		member: 'member'
	};
	for (const [key, value] of Object.entries(all) as [keyof QueryFilters, QueryFilters[keyof QueryFilters]][]) {
		let text = value === null ? '' : String(value).trim();
		if ((key === 'page' && value === 1) || (key === 'pageSize' && value === defaultPageSize)) text = '';
		if (text === '') next.searchParams.delete(keys[key]);
		else next.searchParams.set(keys[key], text);
	}
	return next.pathname + next.search;
}

export type QueryParams = {
	page?: number;
	page_size?: PageSize;
	snapshot?: string;
	from?: string;
	until?: string;
	domain?: string;
	client?: string;
	status?: QueryStatus;
	type?: QueryType;
	result?: QueryResult;
	member?: number;
};

// apiQuery is the API's query parameters for the filters. A preset range is worked out from now, so a reload of
// "the last hour" means the hour before the reload.
export function apiQuery(f: QueryFilters, now = Date.now()): QueryParams {
	const q: QueryParams = {};
	if (f.page !== 1) q.page = f.page;
	if (f.pageSize !== defaultPageSize) q.page_size = f.pageSize;
	if (Object.hasOwn(rangeMs, f.range)) q.from = new Date(now - rangeMs[f.range]).toISOString();
	if (f.range === 'custom') {
		if (f.from) q.from = f.from;
		if (f.until) q.until = f.until;
	}
	if (f.domain) q.domain = f.domain;
	if (f.client) q.client = f.client;
	if (f.status) q.status = f.status;
	if (f.type) q.type = f.type;
	if (f.result) q.result = f.result;
	if (f.member !== null) q.member = f.member;
	return q;
}

// isFiltered reports whether any filter narrows the log (the page, its size and the member don't).
export function isFiltered(f: QueryFilters): boolean {
	return !!(f.domain || f.client || f.range || f.status || f.type || f.result);
}

// The snapshot of the last search, kept in memory so its later pages show the same entries. It never goes in the
// URL, so a bookmarked page shows current data. A search is the target and every filter but the page.
let lastSearch: { key: string; snapshot: string } | null = null;

export function searchKey(target: string, f: QueryFilters): string {
	return JSON.stringify([target, { ...f, page: 0 }]);
}
export function snapshotFor(key: string): string | undefined {
	return lastSearch?.key === key ? lastSearch.snapshot : undefined;
}
export function rememberSnapshot(key: string, snapshot: string): void {
	lastSearch = { key, snapshot };
}
// forgetSnapshot makes the next read a new search, for Refresh.
export function forgetSnapshot(): void {
	lastSearch = null;
}

// pageWindow lists the page numbers the pager shows: the first, the last that can be reached, and those within two
// of the current one, with null where numbers are left out.
export function pageWindow(page: number, pages: number): (number | null)[] {
	if (pages <= 0) return [];
	const keep = new Set([1, pages]);
	for (let p = page - 2; p <= page + 2; p++) if (p >= 1 && p <= pages) keep.add(p);
	const out: (number | null)[] = [];
	let prev = 0;
	for (const p of [...keep].sort((a, b) => a - b)) {
		if (p - prev === 2) out.push(p - 1);
		else if (p - prev > 2) out.push(null);
		out.push(p);
		prev = p;
	}
	return out;
}

const count = new Intl.NumberFormat('en');

// describePage says how many entries match and where the page is: "1,234 queries, page 3 of 50".
export function describePage(total: number, page: number, pages: number): string {
	const n = `${count.format(total)} ${total === 1 ? 'query' : 'queries'}`;
	return pages > 1 ? `${n}, page ${count.format(page)} of ${count.format(pages)}` : n;
}

// The columns that can be hidden, and the browser's memory of which are. Storage can be missing or refuse (private
// windows, policies), so every use is in try/catch and only a convenience is lost.
export const hideableColumns = {
	time: 'Time',
	instance: 'Instance',
	type: 'Type',
	domain: 'Domain',
	client: 'Client',
	status: 'Status',
	reply: 'Reply',
	upstream: 'Upstream'
} as const;
export type ColumnId = keyof typeof hideableColumns;
const columnsKey = 'pihole-rbac.querylog-columns';

export function readHiddenColumns(storage: Pick<Storage, 'getItem'> | undefined): Record<string, boolean> {
	try {
		const raw = JSON.parse(storage?.getItem(columnsKey) ?? '[]');
		const out: Record<string, boolean> = {};
		if (Array.isArray(raw)) for (const id of raw) if (typeof id === 'string' && Object.hasOwn(hideableColumns, id)) out[id] = false;
		return out;
	} catch {
		return {};
	}
}

export function saveHiddenColumns(storage: Pick<Storage, 'setItem'> | undefined, visibility: Record<string, boolean>): void {
	try {
		storage?.setItem(columnsKey, JSON.stringify(Object.keys(visibility).filter((id) => visibility[id] === false)));
	} catch {
		// Not saved; the choice still holds until the page is left.
	}
}

// toLocalInput and fromLocalInput convert between an ISO time and a datetime-local field's value, in local time.
export function toLocalInput(iso: string): string {
	if (!iso) return '';
	const d = new Date(iso);
	const pad = (n: number) => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export function fromLocalInput(value: string): string {
	if (!value) return '';
	const t = new Date(value).getTime(); // a datetime-local value without a zone is local time
	return Number.isNaN(t) ? '' : new Date(t).toISOString();
}

export type StatusKind = 'blocked' | 'allowed' | 'other';

// FTL's status names (Pi-hole v6), what the page calls them, and whether the query was blocked.
export const statuses: Record<QueryStatus, { label: string; kind: StatusKind }> = {
	GRAVITY: { label: 'Blocked (gravity)', kind: 'blocked' },
	GRAVITY_CNAME: { label: 'Blocked (gravity, CNAME)', kind: 'blocked' },
	DENYLIST: { label: 'Blocked (deny list)', kind: 'blocked' },
	DENYLIST_CNAME: { label: 'Blocked (deny list, CNAME)', kind: 'blocked' },
	REGEX: { label: 'Blocked (regex)', kind: 'blocked' },
	REGEX_CNAME: { label: 'Blocked (regex, CNAME)', kind: 'blocked' },
	EXTERNAL_BLOCKED_IP: { label: 'Blocked upstream (IP)', kind: 'blocked' },
	EXTERNAL_BLOCKED_NULL: { label: 'Blocked upstream (null)', kind: 'blocked' },
	EXTERNAL_BLOCKED_NXRA: { label: 'Blocked upstream (NXDOMAIN)', kind: 'blocked' },
	EXTERNAL_BLOCKED_EDE15: { label: 'Blocked upstream (EDE 15)', kind: 'blocked' },
	SPECIAL_DOMAIN: { label: 'Blocked (special domain)', kind: 'blocked' },
	DBBUSY: { label: 'Blocked (database busy)', kind: 'blocked' },
	FORWARDED: { label: 'Forwarded', kind: 'allowed' },
	CACHE: { label: 'Cached', kind: 'allowed' },
	CACHE_STALE: { label: 'Cached (stale)', kind: 'allowed' },
	RETRIED: { label: 'Retried', kind: 'allowed' },
	RETRIED_DNSSEC: { label: 'Retried (DNSSEC)', kind: 'allowed' },
	IN_PROGRESS: { label: 'In progress', kind: 'other' },
	UNKNOWN: { label: 'Unknown', kind: 'other' }
};

// describeStatus names a status; one the page doesn't know (a newer FTL) is shown as sent, and isn't counted as
// either blocked or allowed.
export function describeStatus(status: string): { label: string; kind: StatusKind } {
	return statuses[status as QueryStatus] ?? { label: status || 'Unknown', kind: 'other' };
}

// formatReplyTime gives a reply time in milliseconds, to a precision that suits its size.
export function formatReplyTime(ms: number | undefined): string {
	if (ms === undefined) return '—';
	if (ms < 1) return `${ms.toFixed(2)} ms`;
	if (ms < 100) return `${ms.toFixed(1)} ms`;
	return `${Math.round(ms)} ms`;
}
