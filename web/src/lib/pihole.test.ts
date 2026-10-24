// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { commentProblem, groupNames, type PiholeGroup } from './pihole.js';

describe('commentProblem', () => {
	it('allows up to 500 characters on one line', () => {
		expect(commentProblem('')).toBeNull();
		expect(commentProblem('x'.repeat(500))).toBeNull();
		expect(commentProblem('😀'.repeat(500))).toBeNull(); // characters, not UTF-16 units
		expect(commentProblem('x'.repeat(501))).toMatch(/500/);
		expect(commentProblem('two\nlines')).toMatch(/line breaks/);
	});
});

describe('groupNames', () => {
	const groups: PiholeGroup[] = [
		{ id: 0, name: 'Default', comment: '', enabled: true },
		{ id: 3, name: 'kids', comment: '', enabled: true },
		{ id: 5, name: 'lab', comment: '', enabled: false }
	];

	it("names groups in the Pi-hole's order", () => {
		expect(groupNames([5, 0], groups)).toEqual(['Default', 'lab']);
		expect(groupNames([], groups)).toEqual([]);
	});

	it('shows a group the Pi-hole no longer lists by its ID', () => {
		expect(groupNames([3, 9], groups)).toEqual(['kids', '#9']);
	});
});
