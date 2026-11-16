// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import {
	canChangeStatic,
	canMakeStatic,
	changedSettings,
	expiryText,
	formOf,
	hostnameProblem,
	ipv4,
	ipv4Problem,
	leaseTimeProblem,
	macProblem,
	maskBits,
	normalMac,
	prefixText,
	settingsConfirmation,
	settingsProblems,
	staticIPProblem,
	subnetOf,
	writableProblem,
	type DHCPSettings,
	type SettingsForm
} from './dhcp.js';

const on: DHCPSettings = {
	active: true,
	start: '192.168.1.100',
	end: '192.168.1.200',
	router: '192.168.1.1',
	netmask: '255.255.255.0',
	lease_time: '24h',
	ipv6: false,
	rapid_commit: false,
	multi_dns: false,
	ignore_unknown_clients: false
};

describe('addresses', () => {
	it('reads dotted quads as Go does', () => {
		expect(ipv4('192.168.1.1')).toBe(0xc0a80101);
		expect(ipv4(' 10.0.0.1 ')).toBe(0x0a000001);
		for (const bad of ['', '10.0.0', '10.0.0.256', '010.0.0.1', '1.2.3.4.5', 'a.b.c.d', 'fd00::1', '10.0.0.-1']) expect(ipv4(bad), bad).toBeNull();
	});
	it('refuses addresses a device can not have', () => {
		for (const ok of ['192.168.1.1', '10.0.0.1', '255.255.255.254']) expect(ipv4Problem(ok), ok).toBeNull();
		for (const bad of ['0.0.0.0', '127.0.0.1', '224.0.0.1', '239.255.255.255', '255.255.255.255', 'x']) expect(ipv4Problem(bad), bad).not.toBeNull();
	});
	it('reads netmasks', () => {
		expect(maskBits('255.255.255.0')).toBe(24);
		expect(maskBits('255.255.255.252')).toBe(30);
		expect(maskBits('255.0.0.0')).toBe(8);
		for (const bad of ['255.0.255.0', '0.0.0.0', '255.255.255.255', '255.255.255.254', '1.2.3', '']) expect(maskBits(bad), bad).toBe(-1);
	});
	it('works out the subnet, from the mask or the class', () => {
		const a = subnetOf('192.168.1.100', '255.255.255.0');
		expect(a && prefixText(a)).toBe('192.168.1.0/24');
		expect(a?.guessed).toBe(false);
		expect(a?.broadcast).toBe(ipv4('192.168.1.255'));
		for (const [start, want] of [['10.1.2.3', '10.0.0.0/8'], ['172.16.5.9', '172.16.0.0/16'], ['192.168.7.7', '192.168.7.0/24']]) {
			const s = subnetOf(start, '');
			expect(s && prefixText(s), start).toBe(want);
			expect(s?.guessed).toBe(true);
		}
		expect(subnetOf('nope', '')).toBeNull();
		expect(subnetOf('10.0.0.1', '255.0.255.0')).toBeNull();
	});
});

describe('leaseTimeProblem', () => {
	it('follows the server', () => {
		for (const ok of ['', ' ', '3600', '2m', '120', '24h', '24H', '7d', '1w', '365d', '52w']) expect(leaseTimeProblem(ok), ok).toBeNull();
		for (const bad of ['infinite', '1m', '119', '366d', '53w', '1x', 'h', '-5m', '1.5h', '1h\n2', '9999999999']) expect(leaseTimeProblem(bad), bad).not.toBeNull();
	});
});

describe('settingsProblems', () => {
	const cases: { name: string; change: Partial<SettingsForm>; want: Record<string, string> | null }[] = [
		{ name: 'good settings', change: {}, want: null },
		{ name: 'DHCP off needs nothing set', change: { active: false, start: '', end: '', router: '' }, want: null },
		{ name: 'DHCP on needs the three', change: { start: '', end: ' ', router: '' }, want: { start: 'set', end: 'set', router: 'set' } },
		{ name: 'an address that is not one', change: { end: '192.168.1' }, want: { end: 'valid IPv4' } },
		{ name: 'a netmask that is not one', change: { netmask: '255.0.255.0' }, want: { netmask: 'netmask' } },
		{ name: 'a lease time too short', change: { lease_time: '1m' }, want: { lease_time: '2 minutes' } },
		{ name: 'an address outside the subnet', change: { end: '192.168.2.5' }, want: { end: 'subnet' } },
		{ name: 'the network address', change: { start: '192.168.1.0' }, want: { start: 'network address' } },
		{ name: 'the broadcast address', change: { end: '192.168.1.255' }, want: { end: 'broadcast address' } },
		{ name: 'start after end', change: { start: '192.168.1.201' }, want: { start: 'after' } },
		{ name: 'the router inside the range', change: { router: '192.168.1.150' }, want: { router: 'inside the range' } },
		{ name: 'the router at the range edge', change: { router: '192.168.1.100' }, want: { router: 'inside the range' } },
		{ name: 'an empty netmask guesses the class', change: { netmask: '' }, want: null },
		{ name: 'an empty netmask with a wide class', change: { netmask: '', start: '10.1.1.100', end: '10.1.1.200', router: '10.1.1.1' }, want: null },
		{ name: 'a short mask puts the router outside', change: { netmask: '255.255.255.128', end: '192.168.1.200' }, want: { end: 'subnet' } }
	];
	for (const c of cases) {
		it(c.name, () => {
			const got = settingsProblems({ ...formOf(on), ...c.change });
			if (c.want === null) return expect(got).toEqual({});
			expect(Object.keys(got).sort()).toEqual(Object.keys(c.want).sort());
			for (const [k, part] of Object.entries(c.want)) expect(got[k as keyof typeof got], k).toContain(part);
		});
	}
});

describe('changedSettings', () => {
	it('sends only what differs, trimmed', () => {
		expect(changedSettings(on, formOf(on))).toEqual({});
		expect(changedSettings(on, { ...formOf(on), lease_time: ' 12h ', ipv6: true, router: '192.168.1.2' })).toEqual({
			lease_time: '12h',
			ipv6: true,
			router: '192.168.1.2'
		});
		expect(changedSettings(on, { ...formOf(on), netmask: '' })).toEqual({ netmask: '' });
	});
});

describe('settingsConfirmation', () => {
	const err = (code: string, details: Record<string, unknown>) => new ApiError(409, code, 'm', details);
	it('reads the summary and the other instances', () => {
		expect(settingsConfirmation(err('confirmation_required', { summary: ['Turn DHCP on'], other_active: ['pihole2'] }))).toEqual({
			summary: ['Turn DHCP on'],
			otherActive: ['pihole2']
		});
		expect(settingsConfirmation(err('confirmation_required', {}))).toEqual({ summary: [], otherActive: [] });
	});
	it('ignores other errors', () => {
		expect(settingsConfirmation(err('conflict', {}))).toBeNull();
		expect(settingsConfirmation(new Error('x'))).toBeNull();
	});
});

describe('static leases', () => {
	it('checks hardware addresses', () => {
		for (const ok of ['aa:bb:cc:00:00:01', 'AA-BB-CC-00-00-01', ' 02:00:00:00:00:01 ']) expect(macProblem(ok), ok).toBeNull();
		for (const bad of ['', 'aa:bb', 'aa:bb:cc:00:00:0g', 'aabbcc000001', '01:00:5e:00:00:01', '00:00:00:00:00:00', 'aa:bb:cc:00:00:01:02:03']) {
			expect(macProblem(bad), bad).not.toBeNull();
		}
		expect(normalMac(' AA-BB-CC-00-00-01 ')).toBe('aa:bb:cc:00:00:01');
	});
	it('checks the hostname: optional, one label, not an option', () => {
		for (const ok of ['', ' ', 'nas', 'Printer-2']) expect(hostnameProblem(ok), ok).toBeNull();
		for (const bad of ['nas.lab', 'a b', 'ignore', 'IGNORE', 'infinite', '3600', '12h', '-a', 'a,b']) expect(hostnameProblem(bad), bad).not.toBeNull();
	});
	it('checks the address against the subnet', () => {
		expect(staticIPProblem('192.168.1.10', '192.168.1.0/24')).toBeNull();
		expect(staticIPProblem('192.168.1.10', null)).toBeNull();
		expect(staticIPProblem('10.0.0.5', '192.168.1.0/24')).toMatch(/subnet/);
		expect(staticIPProblem('192.168.1.0', '192.168.1.0/24')).toMatch(/network or broadcast/);
		expect(staticIPProblem('192.168.1.255', '192.168.1.0/24')).toMatch(/network or broadcast/);
		expect(staticIPProblem('nope', '192.168.1.0/24')).toMatch(/IPv4/);
	});
	it('says whether static leases can be changed', () => {
		expect(canChangeStatic({ writable: 'ok', locked: false })).toBe(true);
		expect(canChangeStatic({ writable: 'ok', locked: true })).toBe(false);
		expect(canChangeStatic({ writable: 'app_sudo_off', locked: false })).toBe(false);
		expect(canChangeStatic(undefined)).toBe(false);
	});
	it('offers Make static for IPv4 leases that are not static yet', () => {
		const statics = [{ key: 'k', value: 'v', mac: 'aa:bb:cc:00:00:01', ip: '192.168.1.10', marks: [] }];
		const lease = (over: object) => ({ ipv6: false, hwaddr: 'aa:bb:cc:00:00:09', ip: '192.168.1.50', ...over });
		expect(canMakeStatic(lease({}), statics)).toBe(true);
		expect(canMakeStatic(lease({ ipv6: true }), statics)).toBe(false);
		expect(canMakeStatic(lease({ hwaddr: undefined }), statics)).toBe(false);
		expect(canMakeStatic(lease({ hwaddr: '12345' }), statics)).toBe(false);
		expect(canMakeStatic(lease({ hwaddr: 'AA:BB:CC:00:00:01' }), statics)).toBe(false);
		expect(canMakeStatic(lease({ ip: '192.168.1.10' }), statics)).toBe(false);
	});
});

describe('writableProblem', () => {
	it('says what is missing', () => {
		expect(writableProblem({ instance: 'p', writable: 'ok' })).toBeNull();
		expect(writableProblem({ instance: 'p', writable: 'app_sudo_off' })).toMatch(/app_sudo/);
		expect(writableProblem({ instance: 'p', writable: 'locked' })).toMatch(/read-only/);
		expect(writableProblem({ instance: 'p', writable: 'unknown' })).toMatch(/couldn't be read/);
	});
});

describe('expiryText', () => {
	const now = 1_800_000_000;
	it('says never, ended and how long is left', () => {
		expect(expiryText(0, now)).toBe('Never');
		expect(expiryText(undefined, now)).toBe('Never');
		expect(expiryText(now - 10, now, 'en-GB', 'UTC')).toMatch(/\(ended\)$/);
		expect(expiryText(now + 600, now, 'en-GB', 'UTC')).toMatch(/\(10 min left\)$/);
		expect(expiryText(now + 5 * 3600, now, 'en-GB', 'UTC')).toMatch(/\(5 h left\)$/);
		expect(expiryText(now + 3 * 86400, now, 'en-GB', 'UTC')).not.toMatch(/left/);
	});
});
