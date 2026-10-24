// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { loginURL, safeNext } from './session.svelte.js';

describe('safeNext', () => {
	it.each([
		['/dashboard', '/dashboard'],
		['/domains?target=i-1', '/domains?target=i-1'],
		['/admin/users', '/admin/users']
	])('keeps a path on this site: %s', (next, want) => {
		expect(safeNext(next)).toBe(want);
	});

	it.each([
		[null],
		[''],
		['dashboard'], // relative
		['https://evil.example/'],
		['//evil.example/path'], // protocol-relative
		['/\\evil.example'], // some browsers treat a backslash like a slash
		['javascript:alert(1)']
	])('refuses anything that could leave the site: %j', (next) => {
		expect(safeNext(next)).toBe('/');
	});

	it.each([['/login'], ['/login?next=/dashboard'], ['/setup']])(
		"doesn't send someone back to login or setup: %s",
		(next) => {
			expect(safeNext(next)).toBe('/');
		}
	);
});

describe('loginURL', () => {
	it('carries the page to return to, encoded', () => {
		expect(loginURL('/')).toBe('/login');
		expect(loginURL('/domains?target=i-1')).toBe('/login?next=%2Fdomains%3Ftarget%3Di-1');
	});
});
