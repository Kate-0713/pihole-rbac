// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { domainProblem, entryKey, sameEntry } from './domains.js';

describe('domainProblem', () => {
	it('accepts a domain or regex, ignoring surrounding spaces', () => {
		expect(domainProblem('ads.example', 'exact')).toBeNull();
		expect(domainProblem('  ads.example ', 'exact')).toBeNull();
		expect(domainProblem('(^|\\.)ads\\.example$', 'regex')).toBeNull();
	});

	it('needs something', () => {
		expect(domainProblem('', 'exact')).toMatch(/Enter a domain/);
		expect(domainProblem('   ', 'regex')).toMatch(/Enter a domain/);
	});

	it('allows 255 bytes for a domain and 1024 for a regex, as the server does', () => {
		expect(domainProblem('a'.repeat(255), 'exact')).toBeNull();
		expect(domainProblem('a'.repeat(256), 'exact')).toMatch(/255 bytes/);
		expect(domainProblem('a'.repeat(256), 'regex')).toBeNull();
		expect(domainProblem('a'.repeat(1025), 'regex')).toMatch(/1024 bytes/);
		// Counted in bytes: 128 two-byte characters are 256 bytes.
		expect(domainProblem('é'.repeat(128), 'exact')).toMatch(/255 bytes/);
	});

	it('refuses control characters and line breaks', () => {
		expect(domainProblem('ads.example\nother', 'exact')).toMatch(/control/);
		expect(domainProblem('ads\texample', 'regex')).toMatch(/control/);
	});
});

describe('sameEntry and entryKey', () => {
	it('tell entries apart by domain, list and kind', () => {
		const a = { domain: 'x.example', type: 'deny', kind: 'exact' } as const;
		expect(sameEntry(a, { ...a })).toBe(true);
		expect(sameEntry(a, { ...a, type: 'allow' })).toBe(false);
		expect(sameEntry(a, { ...a, kind: 'regex' })).toBe(false);
		expect(entryKey(a)).not.toBe(entryKey({ ...a, type: 'allow' }));
	});
});
