// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { usesTarget, withTarget } from './targets.svelte.js';

describe('usesTarget', () => {
	it('is true for instance pages and false for admin and account pages', () => {
		for (const p of ['/dashboard', '/domains', '/querylog', '/administrator', '/accounts']) expect(usesTarget(p)).toBe(true);
		for (const p of ['/admin', '/admin/users', '/account', '/account/sessions']) expect(usesTarget(p)).toBe(false);
	});
	it('keeps the target on links that use one', () => {
		expect(withTarget('/domains', 'i-2')).toBe('/domains?target=i-2');
		expect(withTarget('/account/sessions', 'i-2')).toBe('/account/sessions');
	});
});
