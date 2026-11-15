// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, describe, expect, it } from 'vitest';
import {
	apiQuery,
	describePage,
	describeStatus,
	filterProblem,
	filterURL,
	forgetSnapshot,
	formatReplyTime,
	fromLocalInput,
	isFiltered,
	noFilters,
	pageWindow,
	readFilters,
	readHiddenColumns,
	rememberSnapshot,
	saveHiddenColumns,
	searchKey,
	snapshotFor,
	statuses,
	toLocalInput
} from './queries.js';

const read = (search: string) => readFilters(new URLSearchParams(search));

describe('readFilters', () => {
	it('defaults', () => {
		expect(read('')).toEqual(noFilters);
	});

	it('reads every filter', () => {
		expect(
			read('?domain=%20ads%20&client=printer&range=24h&status=GRAVITY&type=AAAA&result=blocked&page=3&page_size=25&member=7')
		).toEqual({
			...noFilters,
			domain: 'ads',
			client: 'printer',
			range: '24h',
			status: 'GRAVITY',
			type: 'AAAA',
			result: 'blocked',
			page: 3,
			pageSize: 25,
			member: 7
		});
	});

	it.each([
		['?page=0', { page: 1 }],
		['?page=1000001', { page: 1 }],
		['?page=2.5', { page: 1 }],
		['?page_size=30', { pageSize: 100 }],
		['?page_size=1000', { pageSize: 100 }],
		['?status=gravity', { status: '' }],
		['?status=toString', { status: '' }],
		['?type=TYPE65', { type: '' }],
		['?result=denied', { result: '' }],
		['?range=2h', { range: '' }],
		['?range=constructor', { range: '' }],
		['?member=abc', { member: null }],
		['?member=0', { member: null }],
		['?domain=a%25b', { domain: '' }],
		['?client=my%20pc', { client: '' }],
		['?client=fd00::1', { client: 'fd00::1' }]
	])('drops what the server would refuse: %s', (search, want) => {
		expect(read(search)).toEqual({ ...noFilters, ...want });
	});

	it('cuts nothing silently: an over-long filter is dropped', () => {
		expect(read('?domain=' + 'x'.repeat(256)).domain).toBe('');
		expect(read('?domain=' + 'x'.repeat(255)).domain).toHaveLength(255);
	});

	it('a custom range keeps its times, in ISO form', () => {
		const f = read('?range=custom&from=2026-11-13T08:00:00Z&until=2026-11-13T09:30:00%2B01:00');
		expect(f).toMatchObject({ range: 'custom', from: '2026-11-13T08:00:00.000Z', until: '2026-11-13T08:30:00.000Z' });
	});

	it('a custom range ending before it starts loses its end; one with no times is no range', () => {
		expect(read('?range=custom&from=2026-11-13T08:00:00Z&until=2026-11-13T07:00:00Z')).toMatchObject({
			range: 'custom',
			until: ''
		});
		expect(read('?range=custom&from=nonsense')).toMatchObject({ range: '', from: '', until: '' });
	});

	it('times are ignored for a preset range', () => {
		expect(read('?range=1h&from=2026-11-13T08:00:00Z')).toMatchObject({ range: '1h', from: '' });
	});
});

describe('filterURL', () => {
	const url = new URL('http://localhost/querylog?target=i-1&domain=old&page=4');

	it('keeps the target, sets the filters, and starts again at page 1', () => {
		expect(filterURL(url, { domain: 'ads', client: '10.0.0.7', pageSize: 50 })).toBe(
			'/querylog?target=i-1&domain=ads&client=10.0.0.7&page_size=50'
		);
	});

	it('turns the page alone', () => {
		expect(filterURL(url, { page: 5 })).toBe('/querylog?target=i-1&domain=old&page=5');
		expect(filterURL(url, { page: 1 })).toBe('/querylog?target=i-1&domain=old');
	});

	it('leaves out empty filters and defaults', () => {
		expect(filterURL(url, { domain: '  ', client: '', pageSize: 100, member: null, status: '' })).toBe(
			'/querylog?target=i-1'
		);
	});

	it('a preset range drops custom times', () => {
		const custom = new URL('http://localhost/querylog?target=i-1&range=custom&from=a&until=b');
		expect(filterURL(custom, { range: '7d' })).toBe('/querylog?target=i-1&range=7d');
		expect(filterURL(custom, { range: 'custom', from: 'x', until: '' })).toBe('/querylog?target=i-1&range=custom&from=x');
	});
});

describe('apiQuery', () => {
	const now = Date.parse('2026-11-14T12:00:00Z');

	it('sends nothing at the defaults', () => {
		expect(apiQuery(noFilters, now)).toEqual({});
	});

	it('works a preset out from now', () => {
		expect(apiQuery({ ...noFilters, range: '1h' }, now)).toEqual({ from: '2026-11-14T11:00:00.000Z' });
		expect(apiQuery({ ...noFilters, range: '30d' }, now)).toEqual({ from: '2026-10-15T12:00:00.000Z' });
	});

	it('sends every filter', () => {
		expect(
			apiQuery(
				{
					...noFilters,
					domain: 'ads',
					client: 'pc',
					range: 'custom',
					from: '2026-11-13T08:00:00.000Z',
					until: '',
					status: 'CACHE',
					type: 'A',
					result: 'cached',
					page: 2,
					pageSize: 250,
					member: 3
				},
				now
			)
		).toEqual({
			domain: 'ads',
			client: 'pc',
			from: '2026-11-13T08:00:00.000Z',
			status: 'CACHE',
			type: 'A',
			result: 'cached',
			page: 2,
			page_size: 250,
			member: 3
		});
	});
});

describe('isFiltered', () => {
	it.each([
		[{}, false],
		[{ page: 3, pageSize: 25 as const, member: 2 }, false],
		[{ domain: 'x' }, true],
		[{ range: '1h' as const }, true],
		[{ result: 'blocked' as const }, true]
	])('%o', (changes, want) => {
		expect(isFiltered({ ...noFilters, ...changes })).toBe(want);
	});
});

describe('filterProblem', () => {
	it.each([
		['domain', 'ads.example', null],
		['domain', '*.tracker-1_x', null],
		['domain', 'fd00::1', 'Letters, digits, dots, hyphens, underscores and * only.'],
		['client', 'fd00::1', null],
		['client', 'my pc', 'Letters, digits, dots, colons, hyphens, underscores and * only.'],
		['client', 'a%b', 'Letters, digits, dots, colons, hyphens, underscores and * only.'],
		['domain', 'x'.repeat(256), 'Up to 255 characters.']
	] as const)('%s %s', (field, value, want) => {
		expect(filterProblem(field, value)).toBe(want);
	});
});

describe('the snapshot', () => {
	afterEach(forgetSnapshot);
	const key = searchKey('i-1', { ...noFilters, domain: 'ads' });

	it('is shared by every page of one search', () => {
		rememberSnapshot(key, 'v1.abc');
		expect(snapshotFor(searchKey('i-1', { ...noFilters, domain: 'ads', page: 7 }))).toBe('v1.abc');
	});

	it('is not used for another search or target', () => {
		rememberSnapshot(key, 'v1.abc');
		expect(snapshotFor(searchKey('i-1', { ...noFilters, domain: 'ad' }))).toBeUndefined();
		expect(snapshotFor(searchKey('i-1', { ...noFilters, domain: 'ads', pageSize: 25 }))).toBeUndefined();
		expect(snapshotFor(searchKey('g-1', { ...noFilters, domain: 'ads' }))).toBeUndefined();
	});

	it('is forgotten on refresh', () => {
		rememberSnapshot(key, 'v1.abc');
		forgetSnapshot();
		expect(snapshotFor(key)).toBeUndefined();
	});
});

describe('pageWindow', () => {
	it.each([
		[1, 0, []],
		[1, 1, [1]],
		[1, 5, [1, 2, 3, 4, 5]],
		[1, 20, [1, 2, 3, null, 20]],
		[10, 20, [1, null, 8, 9, 10, 11, 12, null, 20]],
		[4, 20, [1, 2, 3, 4, 5, 6, null, 20]],
		[20, 20, [1, null, 18, 19, 20]],
		[25, 20, [1, null, 20]]
	])('page %i of %i', (page, pages, want) => {
		expect(pageWindow(page, pages)).toEqual(want);
	});
});

describe('describePage', () => {
	it.each([
		[0, 1, 0, '0 queries'],
		[1, 1, 1, '1 query'],
		[1234, 3, 50, '1,234 queries, page 3 of 50']
	])('%i', (total, page, pages, want) => {
		expect(describePage(total, page, pages)).toBe(want);
	});
});

describe('hidden columns', () => {
	const store = (value: string | null) => ({ getItem: () => value });

	it('reads what was saved, ignoring anything unknown or broken', () => {
		expect(readHiddenColumns(store('["upstream","reply","nonsense",3]'))).toEqual({ upstream: false, reply: false });
		expect(readHiddenColumns(store('{not json'))).toEqual({});
		expect(readHiddenColumns(store(null))).toEqual({});
		expect(readHiddenColumns(undefined)).toEqual({});
		expect(
			readHiddenColumns({
				getItem: () => {
					throw new Error('denied');
				}
			})
		).toEqual({});
	});

	it('saves only the hidden ones, and survives storage refusing', () => {
		let saved = '';
		saveHiddenColumns({ setItem: (_k, v) => (saved = v) }, { upstream: false, time: true });
		expect(saved).toBe('["upstream"]');
		expect(() =>
			saveHiddenColumns(
				{
					setItem: () => {
						throw new Error('full');
					}
				},
				{ upstream: false }
			)
		).not.toThrow();
	});
});

describe('local times', () => {
	it('round-trips through a datetime-local value', () => {
		const iso = '2026-11-13T08:05:00.000Z';
		expect(fromLocalInput(toLocalInput(iso))).toBe(iso);
		expect(toLocalInput('')).toBe('');
		expect(fromLocalInput('')).toBe('');
		expect(fromLocalInput('nonsense')).toBe('');
	});
});

describe('statuses', () => {
	it('names all 19 of FTL’s statuses, the ones the server filters by', () => {
		expect(Object.keys(statuses)).toHaveLength(19);
	});
});

describe('describeStatus', () => {
	it.each([
		['GRAVITY', 'Blocked (gravity)', 'blocked'],
		['DENYLIST', 'Blocked (deny list)', 'blocked'],
		['EXTERNAL_BLOCKED_NXRA', 'Blocked upstream (NXDOMAIN)', 'blocked'],
		['FORWARDED', 'Forwarded', 'allowed'],
		['CACHE', 'Cached', 'allowed'],
		['IN_PROGRESS', 'In progress', 'other'],
		['SOMETHING_NEW', 'SOMETHING_NEW', 'other'],
		['', 'Unknown', 'other']
	])('%s', (status, label, kind) => {
		expect(describeStatus(status)).toEqual({ label, kind });
	});
});

describe('formatReplyTime', () => {
	it.each([
		[undefined, '—'],
		[0.1, '0.10 ms'],
		[12.34, '12.3 ms'],
		[250.6, '251 ms']
	])('%s', (ms, want) => {
		expect(formatReplyTime(ms)).toBe(want);
	});
});
