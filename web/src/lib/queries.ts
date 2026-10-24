// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Schemas } from '#lib/api/client.js';

export type QueryLogEntry = Schemas['QueryLogEntry'];

// How many of the newest entries to read: the choices offered, and the server's default and limits.
export const queryLengths = [100, 250, 500, 1000] as const;
export const defaultLength = 100;
export const maxFilterChars = 255;

export type QueryFilters = { length: number; domain: string; client: string };

// readFilters reads the filters from a URL's query string. A length the server would refuse falls back to the
// default rather than failing the page, since the URL can be typed by hand.
export function readFilters(params: URLSearchParams): QueryFilters {
	const raw = params.get('length');
	const n = raw !== null && /^\d+$/.test(raw) ? Number(raw) : NaN;
	return {
		length: n >= 1 && n <= 1000 ? n : defaultLength,
		domain: (params.get('domain') ?? '').trim().slice(0, maxFilterChars),
		client: (params.get('client') ?? '').trim().slice(0, maxFilterChars)
	};
}

// filterURL returns the path and query string for `url` with the filters changed. Other parameters (the target)
// are kept; an empty filter, or the default length, is left out so the URL stays short. It takes anything with an
// href, because SvelteKit's page.url is a read-only URL; a copy is changed instead.
export function filterURL(url: { readonly href: string }, changes: Partial<QueryFilters>): string {
	const next = new URL(url.href);
	for (const [key, value] of Object.entries(changes)) {
		const text = typeof value === 'number' ? (value === defaultLength ? '' : String(value)) : value.trim();
		if (text === '') next.searchParams.delete(key);
		else next.searchParams.set(key, text);
	}
	return next.pathname + next.search;
}

export type StatusKind = 'blocked' | 'allowed' | 'other';

// FTL's status names (Pi-hole v6), what the page calls them, and whether the query was blocked.
const statuses: Record<string, { label: string; kind: StatusKind }> = {
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
	return statuses[status] ?? { label: status || 'Unknown', kind: 'other' };
}

// formatReplyTime gives a reply time in milliseconds, to a precision that suits its size.
export function formatReplyTime(ms: number | undefined): string {
	if (ms === undefined) return '—';
	if (ms < 1) return `${ms.toFixed(2)} ms`;
	if (ms < 100) return `${ms.toFixed(1)} ms`;
	return `${Math.round(ms)} ms`;
}
