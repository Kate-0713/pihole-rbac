// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	formProblems,
	groupCheckLabel,
	matchedGroups,
	needsPassword,
	passwordStatus,
	plainLDAP,
	sameMethods,
	serverChanged,
	testVerdict,
	toChoice,
	toForm,
	toMethods,
	type LDAPView,
	type UserTest
} from './ldap.js';

const saved = {
	url: 'ldaps://dc01.example.local',
	bind_dn: 'cn=svc,dc=example,dc=local',
	base_dn: 'dc=example,dc=local',
	user_filter: '(uid=%s)',
	tls_mode: 'verify' as const,
	allow_cn_fallback: false
};

const view = (over: Partial<LDAPView> = {}): LDAPView => ({
	enabled: false,
	settings: saved,
	bind_password: { source: 'stored', variable: 'PIHOLE_RBAC_LDAP_BIND_PASSWORD' },
	can_store_password: true,
	ca_file_set: false,
	...over
});

describe('login methods', () => {
	it('round-trips the choice, with local always on', () => {
		expect(toChoice(['local'])).toEqual({ ldap: false, ldapFirst: false });
		expect(toChoice(['ldap', 'local'])).toEqual({ ldap: true, ldapFirst: true });
		expect(toMethods({ ldap: false, ldapFirst: true })).toEqual(['local']);
		expect(toMethods({ ldap: true, ldapFirst: false })).toEqual(['local', 'ldap']);
		expect(toMethods({ ldap: true, ldapFirst: true })).toEqual(['ldap', 'local']);
	});
	it('compares in order', () => {
		expect(sameMethods(['local', 'ldap'], ['local', 'ldap'])).toBe(true);
		expect(sameMethods(['local', 'ldap'], ['ldap', 'local'])).toBe(false);
	});
});

describe('formProblems', () => {
	it('accepts good settings', () => {
		expect(Object.values(formProblems(toForm(saved))).every((p) => p === null)).toBe(true);
		expect(formProblems({ ...toForm(saved), url: 'ldap://10.0.0.5:389' }).url).toBeNull();
	});
	it('catches the server rules', () => {
		const p = formProblems({ ...toForm(saved), url: 'https://dc01', bind_dn: 'svc', base_dn: '', user_filter: '(uid=%s)(cn=%s)' });
		expect(p.url).not.toBeNull();
		expect(p.bind_dn).not.toBeNull();
		expect(p.base_dn).not.toBeNull();
		expect(p.user_filter).not.toBeNull();
		expect(formProblems({ ...toForm(saved), user_filter: '(uid=%s%d)' }).user_filter).not.toBeNull();
		expect(formProblems({ ...toForm(saved), url: 'ldaps://dc01/ou=x' }).url).not.toBeNull();
	});
	it('starts a new form with a usual filter', () => {
		expect(toForm(undefined).user_filter).toBe('(uid=%s)');
		expect(toForm(undefined).tls_mode).toBe('verify');
	});
	it('spots plain ldap', () => {
		expect(plainLDAP(' LDAP://dc01')).toBe(true);
		expect(plainLDAP('ldaps://dc01')).toBe(false);
	});
});

describe('the bind password rule', () => {
	it('asks again for a new server or trust, not for other fields', () => {
		const f = toForm(saved);
		expect(serverChanged(saved, f)).toBe(false);
		expect(serverChanged(saved, { ...f, bind_dn: 'cn=other,dc=example,dc=local' })).toBe(false);
		expect(serverChanged(saved, { ...f, url: 'ldaps://dc02.example.local' })).toBe(true);
		expect(serverChanged(saved, { ...f, url: 'LDAPS://DC01.example.local' })).toBe(false);
		expect(serverChanged(saved, { ...f, tls_mode: 'insecure' })).toBe(true);
		expect(serverChanged(saved, { ...f, allow_cn_fallback: true })).toBe(true);
		expect(serverChanged(undefined, f)).toBe(true);
	});
	it('only when there is a password to protect', () => {
		const moved = { ...toForm(saved), url: 'ldaps://elsewhere' };
		expect(needsPassword(view(), moved)).toBe(true);
		expect(needsPassword(view({ bind_password: { source: 'none', variable: 'X' } }), moved)).toBe(false);
		expect(needsPassword(view({ bind_password: { source: 'environment', variable: 'X' } }), moved)).toBe(true);
	});
	it('describes where the password comes from', () => {
		expect(passwordStatus(view({ bind_password: { source: 'environment', variable: 'PIHOLE_RBAC_LDAP_BIND_PASSWORD' } }))).toContain(
			'From PIHOLE_RBAC_LDAP_BIND_PASSWORD'
		);
		expect(passwordStatus(view({ bind_password: { source: 'none', variable: 'X' } }))).toBe('Not set.');
		const stored = { source: 'stored' as const, variable: 'X', updated_at: '2026-10-24T10:00:00Z', updated_by: 'kate' };
		expect(passwordStatus(view({ bind_password: stored }))).toContain('by kate');
	});
});

describe('directory results', () => {
	it('says what a group check found', () => {
		expect(groupCheckLabel({ exists: true, members: 1 })).toBe('The group exists, with 1 member.');
		expect(groupCheckLabel({ exists: true, members: 3 })).toContain('3 members');
		expect(groupCheckLabel({ exists: false, members: 0 })).toContain('no such group');
	});

	const test = (over: Partial<UserTest> = {}): UserTest => ({
		username: 'lucy',
		found: true,
		dn: 'uid=lucy,dc=x',
		groups: ['CN=Staff, OU=Groups,DC=x', 'cn=other,dc=x'],
		local_account: false,
		mappings: [{ group_dn: 'cn=staff,ou=groups,dc=x', role: { id: 2, name: 'staff' } }],
		roles: [{ id: 2, name: 'staff' }],
		permissions: { global: [], targets: [] },
		...over
	});
	it('sums a test up', () => {
		expect(testVerdict(test())).toEqual({ tone: 'ok', text: 'lucy would log in with: staff.' });
		expect(testVerdict(test({ roles: [], mappings: [] })).text).toContain('would be refused');
		expect(testVerdict(test({ found: false })).text).toContain('no single entry');
		expect(testVerdict(test({ local_account: true })).text).toContain('local account');
	});
	it('finds which groups matched a mapping', () => {
		expect([...matchedGroups(test())]).toEqual(['CN=Staff, OU=Groups,DC=x']);
	});
});
