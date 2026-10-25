// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	emptyForm,
	formChanged,
	formFrom,
	groupProblems,
	mirroredElsewhere,
	sortedMembers,
	toInput,
	type Group,
	type GroupForm
} from './groups.js';

const site: Group = {
	id: 1,
	name: 'Site A',
	mode: 'mirrored',
	primary_instance_id: 2,
	members: [
		{ id: 1, name: 'pihole1', enabled: true },
		{ id: 2, name: 'pihole2', enabled: true },
		{ id: 3, name: 'alpha', enabled: false }
	],
	created_at: '2026-10-25T12:00:00Z'
};
const lab: Group = {
	id: 2,
	name: 'lab',
	mode: 'independent',
	members: [{ id: 4, name: 'pihole4', enabled: true }],
	created_at: '2026-10-25T12:00:00Z'
};
const groups = [site, lab];

const form = (f: Partial<GroupForm>): GroupForm => ({ ...emptyForm(), name: 'new', ...f });

describe('toInput', () => {
	it('sends the primary only for a mirrored group, with members sorted once each', () => {
		expect(toInput({ name: ' x ', mode: 'independent', members: [3, 1, 3], primary: 3 })).toEqual({
			name: 'x',
			mode: 'independent',
			members: [1, 3]
		});
		expect(toInput({ name: 'x', mode: 'mirrored', members: [3, 1], primary: 3 })).toEqual({
			name: 'x',
			mode: 'mirrored',
			members: [1, 3],
			primary_instance_id: 3
		});
	});

	it('round-trips through formFrom', () => {
		expect(toInput(formFrom(site))).toEqual({ name: 'Site A', mode: 'mirrored', members: [1, 2, 3], primary_instance_id: 2 });
		expect(formFrom(lab).primary).toBe(0);
	});
});

describe('mirroredElsewhere', () => {
	it('lists the members of other mirrored groups only', () => {
		expect([...mirroredElsewhere(groups, null)]).toEqual([
			[1, 'Site A'],
			[2, 'Site A'],
			[3, 'Site A']
		]);
		expect(mirroredElsewhere(groups, site.id).size).toBe(0);
	});
});

describe('groupProblems', () => {
	const none = { name: null, members: null, primary: null };

	it('accepts a valid group', () => {
		expect(groupProblems(form({ members: [4] }), groups, null)).toEqual(none);
		expect(groupProblems(form({ mode: 'mirrored', members: [4], primary: 4 }), groups, null)).toEqual(none);
		// Editing a group keeps its own name and members.
		expect(groupProblems(formFrom(site), groups, site.id)).toEqual(none);
	});

	it('checks the name', () => {
		expect(groupProblems(form({ name: '  ' }), groups, null).name).toMatch(/1-64 characters/);
		expect(groupProblems(form({ name: 'LAB' }), groups, null).name).toBe('There is already a group called "lab".');
		expect(groupProblems(form({ name: 'lab' }), groups, lab.id).name).toBeNull();
	});

	it('refuses an instance already in another mirrored group, only for a mirrored group', () => {
		expect(groupProblems(form({ mode: 'mirrored', members: [1, 4], primary: 4 }), groups, null).members).toMatch(
			/already in "Site A"/
		);
		expect(groupProblems(form({ members: [1, 4] }), groups, null).members).toBeNull();
	});

	it('needs a primary among the members of a mirrored group', () => {
		expect(groupProblems(form({ mode: 'mirrored' }), groups, null).primary).toMatch(/at least one member/);
		expect(groupProblems(form({ mode: 'mirrored', members: [4] }), groups, null).primary).toBe(
			'Choose the primary from the members.'
		);
		expect(groupProblems(form({ mode: 'mirrored', members: [4], primary: 5 }), groups, null).primary).not.toBeNull();
		expect(groupProblems(form({ members: [], primary: 0 }), groups, null).primary).toBeNull();
	});

	it('caps the members', () => {
		const many = Array.from({ length: 101 }, (_, i) => i + 10);
		expect(groupProblems(form({ members: many }), groups, null).members).toMatch(/at most 100/);
	});
});

describe('sortedMembers', () => {
	it('puts the primary first, then sorts by name', () => {
		expect(sortedMembers(site).map((m) => m.name)).toEqual(['pihole2', 'alpha', 'pihole1']);
		expect(sortedMembers(lab).map((m) => m.name)).toEqual(['pihole4']);
	});
});

describe('formChanged', () => {
	it('ignores member order and an unused primary', () => {
		const before = formFrom(site);
		expect(formChanged(before, { ...before, members: [3, 2, 1] })).toBe(false);
		expect(formChanged(before, { ...before, name: 'Site B' })).toBe(true);
		expect(formChanged(before, { ...before, primary: 1 })).toBe(true);
		const indep = formFrom(lab);
		expect(formChanged(indep, { ...indep, primary: 4 })).toBe(false);
	});
});
