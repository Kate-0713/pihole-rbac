// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	baseURLProblem,
	caFileProblem,
	connectionChanged,
	envNameProblem,
	errorLabel,
	instanceStatus,
	nameProblem,
	passwordVariable,
	suggestEnvName,
	type Instance
} from './instances.js';

const inst: Instance = {
	id: 1,
	name: 'pihole1',
	base_url: 'https://pihole1.lan',
	env_name: 'PIHOLE1',
	tls_mode: 'verify',
	enabled: true,
	created_at: '2026-10-24T12:00:00Z',
	password_variable: 'PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD',
	password_set: true,
	health: { state: 'up' }
};

describe('passwordVariable', () => {
	it('names the variable the server reads', () => {
		expect(passwordVariable('PIHOLE1')).toBe('PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD');
		expect(passwordVariable('')).toBe('PIHOLE_RBAC_INSTANCE_<ENV_NAME>_PASSWORD');
	});
});

describe('suggestEnvName', () => {
	it.each([
		['pihole1', 'PIHOLE1'],
		['Pi-hole 1', 'PI_HOLE_1'],
		['  site a / lab ', 'SITE_A_LAB'],
		['ümlaut', 'MLAUT'],
		['', '']
	])('%j becomes %j', (name, want) => {
		expect(suggestEnvName(name)).toBe(want);
	});
});

describe('nameProblem', () => {
	it.each([
		['pihole1', false],
		['  Site A  ', false],
		['', true],
		['   ', true],
		['a'.repeat(64), false],
		['a'.repeat(65), true],
		['tab\there', true]
	])('%j: problem %s', (name, bad) => {
		expect(nameProblem(name) !== null).toBe(bad);
	});
});

describe('envNameProblem', () => {
	it.each([
		['PIHOLE1', false],
		['SITE_A_2', false],
		['pihole1', true],
		['PI-HOLE', true],
		['', true],
		['A'.repeat(64), false],
		['A'.repeat(65), true]
	])('%j: problem %s', (env, bad) => {
		expect(envNameProblem(env) !== null).toBe(bad);
	});
});

describe('baseURLProblem', () => {
	it.each([
		['https://pihole1.lan', null],
		['http://192.168.1.2:8080', null],
		['https://proxy.lan/pihole/', null],
		['', "Enter the Pi-hole's address"],
		['pihole1.lan', 'must start with http'],
		['ftp://pihole1.lan', 'must start with http'],
		['https://user:pw@pihole1.lan', 'username or password'],
		['https://pihole1.lan/?x=1', 'query or fragment'],
		['https://pihole1.lan/#top', 'query or fragment'],
		['https://pihole1.lan/admin', 'without /admin or /api'],
		['https://pihole1.lan/admin/', 'without /admin or /api'],
		['https://pihole1.lan/API', 'without /admin or /api'],
		['https://pihole1.lan:99999', "isn't a valid URL"]
	])('%j', (url, want) => {
		const got = baseURLProblem(url);
		if (want === null) expect(got).toBeNull();
		else expect(got).toContain(want);
	});
});

describe('caFileProblem', () => {
	it.each([
		['', 'verify', 'https://p.lan', null],
		['/etc/ssl/pihole-ca.pem', 'verify', 'https://p.lan', null],
		['C:\\certs\\ca.pem', 'verify', 'https://p.lan', null],
		['/etc/ssl/ca.pem', 'insecure', 'https://p.lan', 'only be used when the certificate is verified'],
		['/etc/ssl/ca.pem', 'verify', 'http://p.lan', 'only applies to an https://'],
		['certs/ca.pem', 'verify', 'https://p.lan', 'absolute path']
	] as const)('%j with %s and %s', (file, mode, url, want) => {
		const got = caFileProblem(file, mode, url);
		if (want === null) expect(got).toBeNull();
		else expect(got).toContain(want);
	});
});

describe('instanceStatus', () => {
	it('reads the enabled flag, the password and the health, in that order', () => {
		expect(instanceStatus({ ...inst, enabled: false }).label).toBe('Disabled');
		expect(instanceStatus({ ...inst, password_set: false }).label).toBe('Password missing');
		expect(instanceStatus(inst)).toEqual({ label: 'Up', tone: 'ok' });
		expect(instanceStatus({ ...inst, health: { state: 'down' } }).tone).toBe('bad');
		expect(instanceStatus({ ...inst, health: undefined }).label).toBe('Not checked yet');
	});
});

describe('errorLabel', () => {
	it('names known codes and passes unknown ones through', () => {
		expect(errorLabel('pihole_auth_rejected')).toBe('Pi-hole refused the password');
		expect(errorLabel(undefined)).toBeNull();
		expect(errorLabel('something_new')).toBe('something_new');
	});
});

describe('connectionChanged', () => {
	const same = { name: 'renamed', base_url: 'https://pihole1.lan/', env_name: 'PIHOLE1', tls_mode: 'verify' as const, ca_file: '' };
	it('ignores a rename and a trailing slash', () => {
		expect(connectionChanged(inst, same)).toBe(false);
	});
	it.each([
		['base_url', { base_url: 'https://pihole2.lan' }],
		['env_name', { env_name: 'PIHOLE2' }],
		['tls_mode', { tls_mode: 'insecure' as const }],
		['ca_file', { ca_file: '/etc/ssl/ca.pem' }]
	])('notices %s', (_, change) => {
		expect(connectionChanged(inst, { ...same, ...change })).toBe(true);
	});
});
