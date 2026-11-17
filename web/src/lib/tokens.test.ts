// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	canMakeTokens,
	curlExample,
	dateExpiry,
	dateValue,
	expiresSoon,
	expiryProblem,
	grantableCatalogue,
	maxDateValue,
	presetExpiry,
	stateLabel,
	tokenNameProblem,
	tokenScopes,
	type APIToken,
	type TokenGrantable
} from './tokens.js';

const now = new Date(2026, 10, 17, 12, 0, 0); // 17 Nov 2026, noon local

describe('tokenNameProblem', () => {
	it('accepts a name, trimmed', () => {
		expect(tokenNameProblem('  home assistant ')).toBeNull();
		expect(tokenNameProblem('é'.repeat(64))).toBeNull(); // 64 characters, 128 bytes
	});
	it.each([
		['', 'blank'],
		['   ', 'only spaces'],
		['x'.repeat(65), 'too long'],
		['a\tb', 'a tab'],
		['a\u0085b', 'a C1 control character']
	])('refuses %j (%s)', (name) => {
		expect(tokenNameProblem(name)).not.toBeNull();
	});
});

describe('expiry', () => {
	it('adds whole days for a preset', () => {
		expect(presetExpiry(30, now).getTime() - now.getTime()).toBe(30 * 86400000);
	});

	it('reads a date as the end of that day, locally', () => {
		const d = dateExpiry('2027-03-01')!;
		expect([d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes()]).toEqual([2027, 2, 1, 23, 59]);
		expect(dateExpiry('2027-02-30')).toBeNull();
		expect(dateExpiry('')).toBeNull();
		expect(dateExpiry('next week')).toBeNull();
	});

	it('needs a future date at most a year away', () => {
		expect(expiryProblem(null, now)).not.toBeNull();
		expect(expiryProblem(now, now)).not.toBeNull();
		expect(expiryProblem(new Date(now.getTime() - 1), now)).not.toBeNull();
		expect(expiryProblem(presetExpiry(365, now), now)).toBeNull();
		expect(expiryProblem(new Date(presetExpiry(365, now).getTime() + 1), now)).not.toBeNull();
		expect(expiryProblem(dateExpiry('2026-11-17'), now)).toBeNull(); // later today
	});

	it('writes dates as a date input holds them', () => {
		expect(dateValue(new Date(2027, 2, 1, 23, 59))).toBe('2027-03-01');
	});

	it('offers dates whose end of day still fits in a year', () => {
		const last = maxDateValue(now);
		expect(last).toBe('2027-11-16');
		expect(expiryProblem(dateExpiry(last), now)).toBeNull();
	});
});

const grantable: TokenGrantable = {
	permissions: [
		{ name: 'domains.view', class: 'instance', description: 'List domains', all: false, instances: [2], groups: [9] },
		{ name: 'audit.view', class: 'global', description: 'View the audit log', all: true, instances: [], groups: [] }
	],
	instances: [
		{ id: 1, name: 'pihole1' },
		{ id: 2, name: 'pihole2' }
	],
	groups: [{ id: 9, name: 'site', mode: 'mirrored' }]
};

describe('grantable', () => {
	it('shapes as a catalogue for the grant picker', () => {
		const c = grantableCatalogue(grantable);
		expect(c.permissions).toEqual([
			{ name: 'domains.view', class: 'instance', description: 'List domains' },
			{ name: 'audit.view', class: 'global', description: 'View the audit log' }
		]);
		expect(c.instances).toBe(grantable.instances);
	});

	it('offers only the scopes held', () => {
		const c = grantableCatalogue(grantable);
		expect(tokenScopes(grantable, c.permissions[0])).toEqual({
			all: false,
			instances: [{ id: 2, name: 'pihole2' }],
			groups: [{ id: 9, name: 'site', mode: 'mirrored' }]
		});
		expect(tokenScopes(grantable, c.permissions[1])).toEqual({ all: true, instances: [], groups: [] });
		expect(tokenScopes(grantable, { name: 'dns.restart', class: 'instance', description: '' })).toEqual({
			all: false,
			instances: [],
			groups: []
		});
	});
});

function token(over: Partial<APIToken>): APIToken {
	return {
		public_id: 'abcdefghijklmnop',
		name: 'cron',
		user_id: 1,
		username: 'alice',
		grants: [],
		created_at: '2026-11-01T00:00:00Z',
		expires_at: new Date(now.getTime() + 30 * 86400000).toISOString(),
		last_used_ip: '',
		state: 'active',
		...over
	};
}

describe('token display', () => {
	it('labels states', () => {
		expect(stateLabel(token({}))).toBe('Active');
		expect(stateLabel(token({ state: 'expired' }))).toBe('Expired');
		expect(stateLabel(token({ state: 'revoked' }))).toBe('Revoked');
	});

	it('warns a week before expiry, for active tokens only', () => {
		const soon = new Date(now.getTime() + 6 * 86400000).toISOString();
		expect(expiresSoon(token({ expires_at: soon }), now)).toBe(true);
		expect(expiresSoon(token({}), now)).toBe(false);
		expect(expiresSoon(token({ expires_at: soon, state: 'revoked' }), now)).toBe(false);
	});

	it('puts the token in a header in the example', () => {
		const ex = curlExample('prt_x_y', 'https://pihole-rbac.lab');
		expect(ex).toBe("curl -H 'Authorization: Bearer prt_x_y' https://pihole-rbac.lab/api/v1/targets");
	});
});

describe('canMakeTokens', () => {
	it('needs tokens.use and a local account', () => {
		expect(canMakeTokens(true, 'local')).toBe(true);
		expect(canMakeTokens(true, 'ldap')).toBe(false);
		expect(canMakeTokens(false, 'local')).toBe(false);
		expect(canMakeTokens(true, undefined)).toBe(false);
	});
});
