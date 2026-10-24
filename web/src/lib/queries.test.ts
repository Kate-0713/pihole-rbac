// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { describeStatus, filterURL, formatReplyTime, readFilters } from './queries.js';

describe('readFilters', () => {
	it.each([
		['', { length: 100, domain: '', client: '' }],
		['?length=250&domain=%20ads%20&client=printer', { length: 250, domain: 'ads', client: 'printer' }],
		['?length=1000', { length: 1000, domain: '', client: '' }],
		['?length=0', { length: 100, domain: '', client: '' }],
		['?length=1001', { length: 100, domain: '', client: '' }],
		['?length=12.5', { length: 100, domain: '', client: '' }],
		['?length=-5', { length: 100, domain: '', client: '' }],
		['?length=abc', { length: 100, domain: '', client: '' }]
	])('%s', (search, want) => {
		expect(readFilters(new URLSearchParams(search))).toEqual(want);
	});

	it('cuts a filter to the length the server takes', () => {
		expect(readFilters(new URLSearchParams({ domain: 'x'.repeat(300) })).domain).toHaveLength(255);
	});
});

describe('filterURL', () => {
	const url = new URL('http://localhost/queries?target=i-1&domain=old');

	it('keeps the target and sets the filters', () => {
		expect(filterURL(url, { domain: 'ads', client: '10.0.0.7', length: 500 })).toBe(
			'/queries?target=i-1&domain=ads&client=10.0.0.7&length=500'
		);
	});

	it('leaves out empty filters and the default length', () => {
		expect(filterURL(url, { domain: '  ', client: '', length: 100 })).toBe('/queries?target=i-1');
	});

	it('changes only what it is given', () => {
		expect(filterURL(url, { client: 'printer' })).toBe('/queries?target=i-1&domain=old&client=printer');
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
