// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import {
	descriptionProblem,
	needsConfirmation,
	roleNameProblem,
	sameGrants,
	scopeName,
	scopeOptions,
	summarise,
	toGrants,
	toState,
	wouldLose,
	type Catalogue,
	type Grant
} from './roles.js';

const catalogue: Catalogue = {
	permissions: [
		{ name: 'domains.view', class: 'instance', description: 'List domains' },
		{ name: 'domains.edit', class: 'instance', description: 'Edit domains' },
		{ name: 'drift.view', class: 'group', description: 'Drift report' },
		{ name: 'users.manage', class: 'global', description: 'Users' }
	],
	instances: [
		{ id: 1, name: 'pihole1' },
		{ id: 2, name: 'pihole2' }
	],
	groups: [
		{ id: 1, name: 'site-a', mode: 'mirrored' },
		{ id: 2, name: 'lab', mode: 'independent' }
	]
};

describe('toState and toGrants', () => {
	const grants: Grant[] = [
		{ permission: 'domains.view', scope: 'all' },
		{ permission: 'domains.edit', scope: 'instance', id: 2 },
		{ permission: 'domains.edit', scope: 'instance', id: 1 },
		{ permission: 'domains.edit', scope: 'group', id: 2 },
		{ permission: 'drift.view', scope: 'group', id: 1 },
		{ permission: 'users.manage', scope: 'all' }
	];

	it('round-trip, sorted by catalogue order then ID', () => {
		const state = toState(grants, catalogue);
		expect(Object.keys(state)).toEqual(['domains.view', 'domains.edit', 'drift.view', 'users.manage']);
		expect(state['domains.edit']).toEqual({ all: false, instances: [2, 1], groups: [2] });
		expect(toGrants(state, catalogue)).toEqual([
			{ permission: 'domains.view', scope: 'all' },
			{ permission: 'domains.edit', scope: 'instance', id: 1 },
			{ permission: 'domains.edit', scope: 'instance', id: 2 },
			{ permission: 'domains.edit', scope: 'group', id: 2 },
			{ permission: 'drift.view', scope: 'group', id: 1 },
			{ permission: 'users.manage', scope: 'all' }
		]);
	});

	it('All replaces the separate scopes, which come back when it is unticked', () => {
		const state = toState(grants, catalogue);
		state['domains.edit'].all = true;
		expect(toGrants(state, catalogue).filter((g) => g.permission === 'domains.edit')).toEqual([{ permission: 'domains.edit', scope: 'all' }]);
		state['domains.edit'].all = false;
		expect(toGrants(state, catalogue).filter((g) => g.permission === 'domains.edit')).toHaveLength(3);
	});

	it('keeps a permission the catalogue no longer lists, rather than dropping it silently', () => {
		const state = toState([{ permission: 'old.perm', scope: 'all' }], catalogue);
		expect(toGrants(state, catalogue)).toEqual([{ permission: 'old.perm', scope: 'all' }]);
	});
});

describe('sameGrants', () => {
	it('ignores order and duplicates', () => {
		const a: Grant[] = [
			{ permission: 'domains.view', scope: 'all' },
			{ permission: 'domains.edit', scope: 'instance', id: 1 }
		];
		expect(sameGrants(a, [...a].reverse())).toBe(true);
		expect(sameGrants(a, [...a, a[0]])).toBe(true);
		expect(sameGrants(a, [a[0], { permission: 'domains.edit', scope: 'instance', id: 2 }])).toBe(false);
		expect(sameGrants(a, [a[0]])).toBe(false);
	});
});

describe('scopeOptions', () => {
	it('follows the permission classes', () => {
		const [view, , drift, users] = catalogue.permissions;
		expect(scopeOptions(view, catalogue)).toEqual({ instances: catalogue.instances, groups: catalogue.groups });
		expect(scopeOptions(drift, catalogue)).toEqual({ instances: [], groups: [catalogue.groups[0]] });
		expect(scopeOptions(users, catalogue)).toEqual({ instances: [], groups: [] });
	});
});

describe('scopeName and summarise', () => {
	it('names scopes, falling back to IDs', () => {
		expect(scopeName({ permission: 'x', scope: 'all' }, catalogue)).toBe('all instances');
		expect(scopeName({ permission: 'x', scope: 'instance', id: 2 }, catalogue)).toBe('pihole2');
		expect(scopeName({ permission: 'x', scope: 'group', id: 1 }, catalogue)).toBe('group site-a');
		expect(scopeName({ permission: 'x', scope: 'instance', id: 9 }, catalogue)).toBe('instance #9');
	});

	it('summarises one line per permission, without a scope for global ones', () => {
		const grants: Grant[] = [
			{ permission: 'domains.edit', scope: 'instance', id: 1 },
			{ permission: 'domains.edit', scope: 'group', id: 1 },
			{ permission: 'users.manage', scope: 'all' }
		];
		expect(summarise(grants, catalogue)).toEqual(['domains.edit: pihole1, group site-a', 'users.manage']);
		expect(summarise(grants, null)).toEqual(['domains.edit: instance #1, group #1', 'users.manage: all instances']);
	});
});

describe('roleNameProblem and descriptionProblem', () => {
	it.each([
		['staff', false],
		['  padded  ', false],
		['', true],
		['a'.repeat(65), true],
		['tab\there', true]
	])('name %j: problem %s', (name, bad) => {
		expect(roleNameProblem(name) !== null).toBe(bad);
	});
	it.each([
		['', false],
		['two\nlines\tand a tab', false],
		['bell\u0007', true],
		['x'.repeat(501), true]
	])('description %j: problem %s', (d, bad) => {
		expect(descriptionProblem(d) !== null).toBe(bad);
	});
});

describe('needsConfirmation and wouldLose', () => {
	it('spots the 409 and reads what would be lost', () => {
		const e = new ApiError(409, 'confirmation_required', 'Confirm', { would_lose: ['roles.manage'] });
		expect(needsConfirmation(e)).toBe(true);
		expect(wouldLose(e)).toEqual(['roles.manage']);
		expect(wouldLose(new ApiError(409, 'confirmation_required', 'Confirm', { would_lose: 'account' }))).toEqual(['account']);
		expect(needsConfirmation(new ApiError(409, 'conflict', 'Taken'))).toBe(false);
		expect(needsConfirmation(new Error('x'))).toBe(false);
	});
});
