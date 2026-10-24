// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { Role } from './roles.js';
import { confirmText, isSelf, roleChoices, rolesSummary, sameRoles, sourceLabel, userActions, type User } from './users.js';

const user = (over: Partial<User> = {}): User => ({
	id: 2,
	username: 'erin',
	source: 'local',
	disabled: false,
	created_at: '2026-10-24T10:00:00Z',
	roles: [],
	manageable: true,
	...over
});

const role = (id: number, name: string, manageable = true): Role => ({
	id,
	name,
	description: '',
	builtin: false,
	created_at: '2026-10-24T10:00:00Z',
	grants: [],
	users: [],
	ldap_groups: [],
	manageable
});

describe('rolesSummary', () => {
	it('lists the roles by name', () => {
		expect(rolesSummary(user({ roles: [{ id: 1, name: 'admin' }, { id: 3, name: 'staff' }] }))).toBe('admin, staff');
	});
	it("says a local user without a role can't log in", () => {
		expect(rolesSummary(user())).toBe("None (can't log in)");
	});
	it('says where an LDAP user gets roles when none are known', () => {
		expect(rolesSummary(user({ source: 'ldap' }))).toBe('From LDAP groups at login');
	});
});

describe('sourceLabel and userActions', () => {
	it('offers roles and passwords for local users only', () => {
		expect(sourceLabel(user())).toBe('Local');
		expect(userActions(user())).toEqual({ roles: true, password: true });
		expect(sourceLabel(user({ source: 'ldap' }))).toBe('LDAP');
		expect(userActions(user({ source: 'ldap' }))).toEqual({ roles: false, password: false });
	});
});

describe('roleChoices', () => {
	it('sorts by name and only lets the caller change roles they hold all of', () => {
		const choices = roleChoices([role(2, 'staff'), role(1, 'admin', false)]);
		expect(choices.map((c) => [c.role.name, c.selectable])).toEqual([
			['admin', false],
			['staff', true]
		]);
	});
});

describe('sameRoles', () => {
	it('ignores order', () => {
		expect(sameRoles([1, 2], [2, 1])).toBe(true);
		expect(sameRoles([1, 2], [1])).toBe(false);
		expect(sameRoles([1, 2], [1, 3])).toBe(false);
		expect(sameRoles([], [])).toBe(true);
	});
});

describe('isSelf', () => {
	it('matches the session user', () => {
		expect(isSelf(user({ id: 4 }), 4)).toBe(true);
		expect(isSelf(user({ id: 4 }), 5)).toBe(false);
		expect(isSelf(user({ id: 4 }), undefined)).toBe(false);
	});
});

describe('confirmText', () => {
	it('warns about your own account', () => {
		expect(confirmText('disable', user(), true)).toContain('You will be logged out');
		expect(confirmText('delete', user(), true)).toContain('Your account is removed');
	});
	it('explains what happens to someone else', () => {
		expect(confirmText('disable', user(), false)).toContain("erin is logged out at once and can't log in");
		expect(confirmText('delete', user(), false)).toContain("erin's account, roles and sessions are removed");
		expect(confirmText('delete', user({ source: 'ldap' }), false)).toContain('new account when they next do');
	});
});
