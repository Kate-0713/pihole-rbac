// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import type { User } from '#lib/users.js';
import { codeReady, groupSecret, policyLabel, recoveryCodesFile, restartsLogin, twoFactorSummary } from './totp.js';

describe('restartsLogin', () => {
	it.each([
		['login_expired', 401],
		['invalid_credentials', 401],
		['no_access', 403]
	])('goes back to the password for %s', (code, status) => {
		expect(restartsLogin(new ApiError(status, code, 'x'))).toBe(true);
	});

	it.each([
		['totp_invalid', 401],
		['rate_limited', 429],
		['validation_failed', 400],
		['network_error', 0],
		['internal', 500]
	])('keeps the code form for %s', (code, status) => {
		expect(restartsLogin(new ApiError(status, code, 'x'))).toBe(false);
	});

	it('keeps the code form for an error that is not from the server', () => {
		expect(restartsLogin(new Error('boom'))).toBe(false);
		expect(restartsLogin(undefined)).toBe(false);
	});
});

describe('groupSecret', () => {
	it('splits into fours', () => {
		expect(groupSecret('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toBe('GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ');
		expect(groupSecret('ABCDEF')).toBe('ABCD EF');
		expect(groupSecret('')).toBe('');
	});
});

describe('codeReady', () => {
	it.each([
		['123456', false, true],
		['123 456', false, true],
		[' 123456 ', false, true],
		['12345', false, false],
		['1234567', false, false],
		['12345a', false, false],
		['abcd-efgh-ijkl-mnop', false, false],
		['abcd-efgh-ijkl-mnop', true, true],
		['ABCD EFGH IJKL MNOP', true, true],
		['abcdefghijklmnop', true, true],
		['abcd-efgh-ijkl-mn0p', true, false], // 0 isn't base32
		['abcd-efgh-ijkl', true, false],
		['', true, false]
	])('%j, recovery codes %s: %s', (input, recovery, want) => {
		expect(codeReady(input, recovery)).toBe(want);
	});
});

describe('recoveryCodesFile', () => {
	it('names the account and the time, then lists the codes', () => {
		const text = recoveryCodesFile(['aaaa-bbbb-cccc-dddd', 'eeee-ffff-gggg-hhhh'], 'alice', new Date('2026-11-16T23:05:09Z'), 'pihole.lab');
		expect(text).toBe(
			'pihole-rbac recovery codes for alice on pihole.lab\n' +
				'Made 2026-11-16 23:05 UTC. Each works once, in place of a code from your\n' +
				'authenticator app. Getting new ones makes these stop working.\n' +
				'\n' +
				'aaaa-bbbb-cccc-dddd\n' +
				'eeee-ffff-gggg-hhhh\n'
		);
	});
});

describe('policyLabel', () => {
	it('names each setting', () => {
		expect(policyLabel('roles')).toBe('Follows their roles');
		expect(policyLabel('required')).toBe('Required for this user');
		expect(policyLabel('exempt')).toBe('Not required for this user');
	});
});

describe('twoFactorSummary', () => {
	const user = (over: Partial<User>): User => ({
		id: 2,
		username: 'erin',
		source: 'local',
		disabled: false,
		totp_enabled: false,
		totp_policy: 'roles',
		totp_required: false,
		created_at: '2026-10-24T10:00:00Z',
		roles: [],
		manageable: true,
		...over
	});
	it('says on, missing or off', () => {
		expect(twoFactorSummary(user({ totp_enabled: true, totp_required: true }))).toEqual({ label: 'On', tone: 'on' });
		expect(twoFactorSummary(user({ totp_enabled: true }))).toEqual({ label: 'On', tone: 'on' });
		expect(twoFactorSummary(user({ totp_required: true }))).toEqual({ label: 'Required, not set up', tone: 'missing' });
		expect(twoFactorSummary(user({}))).toEqual({ label: 'Off', tone: 'off' });
	});
});
