// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The users page's helpers: how a user's roles and state read in the table, which roles the caller can give, and
// what a change to your own account means. Plain TypeScript, so it is tested without a browser. The server checks
// every rule again; these only shape what the page offers.
import type { Schemas } from '#lib/api/client.js';
import type { Role } from '#lib/roles.js';

export type User = Schemas['User'];

// rolesSummary is the table's roles column.
export function rolesSummary(u: User): string {
	if (u.roles.length > 0) return u.roles.map((r) => r.name).join(', ');
	// An LDAP user's roles are only known while they have a session; they come from the directory at login.
	if (u.source === 'ldap') return 'From LDAP groups at login';
	return "None (can't log in)";
}

// sourceLabel names where the account lives.
export function sourceLabel(u: User): string {
	return u.source === 'ldap' ? 'LDAP' : 'Local';
}

// What the actions menu offers for a user. Changing roles and setting a password are for local users: an LDAP
// user's roles come from group mappings and their password lives in the directory.
export function userActions(u: User): { roles: boolean; password: boolean } {
	const local = u.source === 'local';
	return { roles: local, password: local };
}

// RoleChoice is one box of the role checklist: whether the caller may tick or untick it.
export type RoleChoice = { role: Role; selectable: boolean };

// roleChoices lists every role for the checklist, by name. Giving or taking away a role needs every grant it has,
// which is what `manageable` says, so the others are shown but can't be changed.
export function roleChoices(roles: readonly Role[]): RoleChoice[] {
	return [...roles]
		.sort((a, b) => a.name.localeCompare(b.name))
		.map((role) => ({ role, selectable: role.manageable }));
}

// sameRoles says whether two lists of role IDs hold the same roles, in any order.
export function sameRoles(a: readonly number[], b: readonly number[]): boolean {
	if (a.length !== b.length) return false;
	const set = new Set(a);
	return b.every((id) => set.has(id));
}

// isSelf says whether a user is the one logged in.
export function isSelf(u: User, sessionUserID: number | undefined): boolean {
	return sessionUserID !== undefined && u.id === sessionUserID;
}

// What disabling or deleting a user says before it goes ahead.
export function confirmText(action: 'disable' | 'delete', u: User, self: boolean): string {
	if (action === 'disable') {
		if (self) return 'You will be logged out at once, and can only get back in once someone enables your account.';
		return `${u.username} is logged out at once and can't log in until enabled again. Their roles are kept.`;
	}
	if (self) return 'Your account is removed and you are logged out at once. The audit log keeps your username.';
	if (u.source === 'ldap') {
		return (
			`${u.username}'s account and sessions are removed. If they can still log in through LDAP, they get a new ` +
			'account when they next do. The audit log keeps their username.'
		);
	}
	return `${u.username}'s account, roles and sessions are removed. The audit log keeps their username.`;
}
