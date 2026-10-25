// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	apiQuery,
	auditURL,
	describeRetention,
	detailText,
	emptyFilters,
	errorOf,
	exportHref,
	filtersActive,
	fromLocalInput,
	parseActions,
	readAuditFilters,
	retentionProblem,
	timeProblem,
	toLocalInput,
	type AuditEntry,
	type AuditFilters
} from './audit.js';

const read = (search: string) => readAuditFilters(new URLSearchParams(search));

describe('readAuditFilters', () => {
	it('reads every filter, with the target as `on`', () => {
		expect(
			read('?user=alice&action=domain_add&action=login&on=i-1&instance_id=3&result=failure&from=2026-10-01T12:00:00Z&to=2026-10-02T12:00:00%2B01:00')
		).toEqual({
			user: 'alice',
			actions: ['domain_add', 'login'],
			target: 'i-1',
			instanceId: 3,
			result: 'failure',
			from: '2026-10-01T12:00:00.000Z',
			to: '2026-10-02T11:00:00.000Z'
		});
	});

	it('is empty for no query string', () => {
		expect(read('')).toEqual(emptyFilters);
	});

	it.each([
		['?action=Login&action=domain-add&action=ok_one', { actions: ['ok_one'] }],
		['?action=login&action=login', { actions: ['login'] }],
		['?instance_id=0', { instanceId: null }],
		['?instance_id=1.5', { instanceId: null }],
		['?instance_id=abc', { instanceId: null }],
		['?result=maybe', { result: '' }],
		['?from=yesterday', { from: '' }],
		[`?user=${'u'.repeat(257)}`, { user: '' }],
		[`?on=${'t'.repeat(513)}`, { target: '' }],
		// An end before the start is dropped, keeping the start.
		['?from=2026-10-02T00:00:00Z&to=2026-10-01T00:00:00Z', { from: '2026-10-02T00:00:00.000Z', to: '' }],
		// A ?target= is the instance the other pages act on, never a filter.
		['?target=i-1', { target: '' }]
	])('drops what the server would refuse: %s', (search, want) => {
		expect(read(search)).toEqual({ ...emptyFilters, ...want });
	});

	it('takes at most 50 actions', () => {
		const many = Array.from({ length: 60 }, (_, i) => `action=a${String.fromCharCode(97 + (i % 26))}${'_'.repeat(Math.floor(i / 26))}`);
		expect(read('?' + many.join('&')).actions).toHaveLength(50);
	});
});

describe('auditURL and filtersActive', () => {
	const f: AuditFilters = { ...emptyFilters, user: 'bob', actions: ['login', 'logout'], target: 'user:carol', instanceId: 2, result: 'success' };

	it('round-trips through the URL', () => {
		const url = auditURL(f);
		expect(url).toBe('/admin/audit?user=bob&action=login&action=logout&on=user%3Acarol&instance_id=2&result=success');
		expect(read(url.slice(url.indexOf('?')))).toEqual(f);
	});

	it('leaves out empty filters', () => {
		expect(auditURL(emptyFilters)).toBe('/admin/audit');
		expect(filtersActive(emptyFilters)).toBe(false);
		expect(filtersActive({ ...emptyFilters, to: '2026-10-01T00:00:00.000Z' })).toBe(true);
	});
});

describe('apiQuery and exportHref', () => {
	it('names the target filter as the API does', () => {
		const f: AuditFilters = { ...emptyFilters, target: 'i-1', actions: ['domain_add'], from: '2026-10-01T00:00:00.000Z' };
		expect(apiQuery(f)).toEqual({ target: 'i-1', action: ['domain_add'], from: '2026-10-01T00:00:00.000Z' });
		expect(apiQuery(emptyFilters)).toEqual({});
	});

	it('repeats actions in the export link', () => {
		expect(exportHref({ ...emptyFilters, actions: ['login', 'logout'], result: 'failure' })).toBe(
			'/api/v1/audit/export?action=login&action=logout&result=failure'
		);
		expect(exportHref(emptyFilters)).toBe('/api/v1/audit/export');
	});
});

describe('parseActions', () => {
	it.each([
		['', [], null],
		['login', ['login'], null],
		['domain_add, login  logout,login', ['domain_add', 'login', 'logout'], null]
	])('%s', (text, actions, problem) => {
		expect(parseActions(text)).toEqual({ actions, problem });
	});

	it('names a bad action', () => {
		expect(parseActions('login, Domain_Add').problem).toContain('"Domain_Add" isn\'t an action name');
	});
});

describe('local times', () => {
	it('round-trips through a datetime-local value, to the minute', () => {
		const iso = '2026-10-25T16:41:00.000Z';
		expect(fromLocalInput(toLocalInput(iso))).toBe(iso);
	});

	it('treats empty and bad values as none', () => {
		expect(toLocalInput('')).toBe('');
		expect(toLocalInput('nope')).toBe('');
		expect(fromLocalInput('')).toBe('');
		expect(fromLocalInput('nope')).toBe('');
	});

	it('checks the range', () => {
		expect(timeProblem('', '2026-10-01T00:00:00.000Z')).toBeNull();
		expect(timeProblem('2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z')).toBeNull();
		expect(timeProblem('2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z')).toContain('must be after');
	});
});

describe('entries', () => {
	const entry = (detail: Record<string, unknown>): AuditEntry => ({
		id: 1, at: '2026-10-01T12:00:00Z', username: 'alice', action: 'login', target: '', instance_name: '',
		result: 'failure', detail, ip: ''
	});

	it('shows the detail as indented JSON, or nothing', () => {
		expect(detailText({})).toBe('');
		expect(detailText({ domain: 'example.com' })).toBe('{\n  "domain": "example.com"\n}');
	});

	it('finds the error', () => {
		expect(errorOf(entry({ error: 'wrong password' }))).toBe('wrong password');
		expect(errorOf(entry({ error: 42 }))).toBe('');
		expect(errorOf(entry({}))).toBe('');
	});
});

describe('retention', () => {
	it.each([
		[30, null],
		[365, null],
		[3650, null],
		[29, 'Use 30 to 3650 days (10 years).'],
		[3651, 'Use 30 to 3650 days (10 years).'],
		[90.5, 'Use 30 to 3650 days (10 years).'],
		[Number.NaN, 'Use 30 to 3650 days (10 years).']
	])('%s days', (days, want) => {
		expect(retentionProblem(days)).toBe(want);
	});

	it.each([
		[365, '1 year'],
		[730, '2 years'],
		[90, '90 days']
	])('describes %s days', (days, want) => {
		expect(describeRetention(days)).toBe(want);
	});
});
