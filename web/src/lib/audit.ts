// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Schemas } from '#lib/api/client.js';

export type AuditEntry = Schemas['AuditEntry'];
export type AuditList = Schemas['AuditList'];

// The audit page's filters, as they live in its URL. The target filter is `on` in the URL, not `target`: admin pages
// drop a ?target= parameter, since that names the instance the other pages act on.
export type AuditFilters = {
	user: string;
	actions: string[];
	target: string;
	instanceId: number | null;
	result: '' | 'success' | 'failure';
	from: string; // RFC 3339, or ''
	to: string;
};

export const emptyFilters: AuditFilters = { user: '', actions: [], target: '', instanceId: null, result: '', from: '', to: '' };

// The server's limits, so the page refuses what the server would.
export const maxUser = 256;
export const maxTarget = 512;
export const maxActions = 50;
const actionPattern = /^[a-z][a-z_]{0,63}$/;

// The URL's parameter for each filter.
const param = { user: 'user', actions: 'action', target: 'on', instanceId: 'instance_id', result: 'result', from: 'from', to: 'to' } as const;

function validTime(s: string): boolean {
	return s !== '' && !Number.isNaN(new Date(s).getTime());
}

// readAuditFilters reads the filters from the page's query string. The URL can be typed by hand, so a value the
// server would refuse is dropped rather than failing the page.
export function readAuditFilters(params: URLSearchParams): AuditFilters {
	const user = (params.get(param.user) ?? '').trim();
	const target = (params.get(param.target) ?? '').trim();
	const id = params.get(param.instanceId) ?? '';
	const result = params.get(param.result);
	const from = params.get(param.from) ?? '';
	const to = params.get(param.to) ?? '';
	const actions = [...new Set(params.getAll(param.actions).filter((a) => actionPattern.test(a)))].slice(0, maxActions);
	const f: AuditFilters = {
		user: user.length <= maxUser ? user : '',
		actions,
		target: target.length <= maxTarget ? target : '',
		instanceId: /^[1-9]\d{0,15}$/.test(id) ? Number(id) : null,
		result: result === 'success' || result === 'failure' ? result : '',
		from: validTime(from) ? new Date(from).toISOString() : '',
		to: validTime(to) ? new Date(to).toISOString() : ''
	};
	if (f.from && f.to && f.to <= f.from) f.to = '';
	return f;
}

// filtersActive says whether any filter is set.
export function filtersActive(f: AuditFilters): boolean {
	return f.user !== '' || f.actions.length > 0 || f.target !== '' || f.instanceId !== null || f.result !== '' || f.from !== '' || f.to !== '';
}

// auditURL returns the page's path with these filters; empty ones are left out so the URL stays short.
export function auditURL(f: AuditFilters, path = '/admin/audit'): string {
	const p = new URLSearchParams();
	if (f.user) p.set(param.user, f.user);
	for (const a of f.actions) p.append(param.actions, a);
	if (f.target) p.set(param.target, f.target);
	if (f.instanceId !== null) p.set(param.instanceId, String(f.instanceId));
	if (f.result) p.set(param.result, f.result);
	if (f.from) p.set(param.from, f.from);
	if (f.to) p.set(param.to, f.to);
	const q = p.toString();
	return q ? `${path}?${q}` : path;
}

// The API's query parameters for the list and the export. Only the target filter's name differs from the page's URL.
export type AuditQuery = {
	user?: string;
	action?: string[];
	target?: string;
	instance_id?: number;
	result?: 'success' | 'failure';
	from?: string;
	to?: string;
};

export function apiQuery(f: AuditFilters): AuditQuery {
	const q: AuditQuery = {};
	if (f.user) q.user = f.user;
	if (f.actions.length > 0) q.action = f.actions;
	if (f.target) q.target = f.target;
	if (f.instanceId !== null) q.instance_id = f.instanceId;
	if (f.result) q.result = f.result;
	if (f.from) q.from = f.from;
	if (f.to) q.to = f.to;
	return q;
}

// exportHref is the CSV download for these filters. A plain link works: it's a GET, and the session cookie goes with a
// same-site navigation.
export function exportHref(f: AuditFilters): string {
	const p = new URLSearchParams();
	for (const [k, v] of Object.entries(apiQuery(f))) {
		for (const one of Array.isArray(v) ? v : [v]) p.append(k, String(one));
	}
	const q = p.toString();
	return q ? `/api/v1/audit/export?${q}` : '/api/v1/audit/export';
}

// parseActions reads the action field: names separated by commas or spaces. It returns the names, or a problem.
export function parseActions(text: string): { actions: string[]; problem: string | null } {
	const actions = [...new Set(text.split(/[\s,]+/).filter((a) => a !== ''))];
	const bad = actions.find((a) => !actionPattern.test(a));
	if (bad !== undefined) return { actions, problem: `"${bad}" isn't an action name: lower-case letters and underscores, like domain_add.` };
	if (actions.length > maxActions) return { actions, problem: `At most ${maxActions} actions.` };
	return { actions, problem: null };
}

const pad = (n: number) => String(n).padStart(2, '0');

// toLocalInput turns an RFC 3339 time into the value of an <input type="datetime-local">, in the browser's time zone.
export function toLocalInput(rfc3339: string): string {
	if (!validTime(rfc3339)) return '';
	const d = new Date(rfc3339);
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// fromLocalInput turns a datetime-local value, which is in the browser's time zone, into RFC 3339 UTC; '' for none.
export function fromLocalInput(value: string): string {
	if (value === '') return '';
	const d = new Date(value); // a date-time without an offset is local time
	return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

// timeProblem checks a time range as entered.
export function timeProblem(from: string, to: string): string | null {
	return from && to && to <= from ? 'The end of the time range must be after its start.' : null;
}

// detailText shows an entry's detail for reading: indented JSON, with the keys in the order the server sent them.
// It's shown as text, never as HTML.
export function detailText(detail: Record<string, unknown>): string {
	return Object.keys(detail).length === 0 ? '' : JSON.stringify(detail, null, 2);
}

// errorOf returns the failure's message from the detail, or ''.
export function errorOf(e: AuditEntry): string {
	const err = e.detail['error'];
	return typeof err === 'string' ? err : '';
}

// Audit retention, as on the settings page.
export const retentionRange = { min: 30, max: 3650 };

export function retentionProblem(days: number): string | null {
	return !Number.isInteger(days) || days < retentionRange.min || days > retentionRange.max
		? `Use ${retentionRange.min} to ${retentionRange.max} days (10 years).`
		: null;
}

// describeRetention says how long entries are kept, in words.
export function describeRetention(days: number): string {
	if (days % 365 === 0) return days === 365 ? '1 year' : `${days / 365} years`;
	return `${days} days`;
}
