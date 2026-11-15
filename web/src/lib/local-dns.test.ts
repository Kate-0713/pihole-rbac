// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import {
	canChange,
	cnameRow,
	describe as describeEntry,
	directoryConfirmation,
	ipProblem,
	nameProblem,
	reasonProblem,
	recordRow,
	ttlProblem,
	writable,
	writableProblem,
	type LocalDNSInstance
} from './local-dns.js';

describe('nameProblem', () => {
	it('follows the server', () => {
		for (const ok of ['nas', 'nas.lab', 'NAS.Lab', ' a-b.c ', 'xn--bcher-kva.lab', `${'a'.repeat(63)}.lab`]) {
			expect(nameProblem(ok), ok).toBeNull();
		}
		for (const bad of ['', 'nas.lab.', '.nas', 'a..b', '-a.lab', 'a-.lab', 'my_host', 'a b', 'a,b', 'a#b', 'bücher.lab', `${'a'.repeat(64)}.lab`]) {
			expect(nameProblem(bad), bad).not.toBeNull();
		}
		expect(nameProblem('a.'.repeat(126) + 'ab')).toMatch(/253/);
	});
});

describe('ipProblem', () => {
	it('takes IPv4 and IPv6 without a zone', () => {
		for (const ok of ['10.0.0.5', '0.0.0.0', 'fd00::5', '::1', '::ffff:10.0.0.5', ' 10.0.0.5 ']) expect(ipProblem(ok), ok).toBeNull();
		for (const bad of ['', '10.0.0', '10.0.0.256', '010.0.0.1', 'fe80::1%eth0', 'nas.lab', '10.0.0.5/24', 'fd00:::5']) {
			expect(ipProblem(bad), bad).not.toBeNull();
		}
	});
});

describe('ttlProblem and reasonProblem', () => {
	it('checks the TTL', () => {
		expect(ttlProblem('')).toBeNull();
		expect(ttlProblem('0')).toBeNull();
		expect(ttlProblem('86400')).toBeNull();
		for (const bad of ['86401', '-1', '1.5', 'x']) expect(ttlProblem(bad), bad).not.toBeNull();
	});
	it('checks the reason, required or not', () => {
		expect(reasonProblem('  ', true)).toMatch(/Give a reason/);
		expect(reasonProblem('', false)).toBeNull();
		expect(reasonProblem('x'.repeat(200), true)).toBeNull();
		expect(reasonProblem('x'.repeat(201), false)).toMatch(/200/);
		expect(reasonProblem('a\nb', true)).toMatch(/line breaks/);
	});
});

describe('rows', () => {
	it('turns records and CNAMEs into rows', () => {
		const r = recordRow({ key: '10.0.0.6 a b', value: '10.0.0.6 a b # x', ip: '10.0.0.6', hostnames: ['a', 'b'], comment: 'x', marks: ['multiple_names', 'comment'] });
		expect(r).toMatchObject({ kind: 'record', name: 'a', points: '10.0.0.6', extra: ['b'] });
		expect(writable(r)).toBe(false);
		const c = cnameRow({ key: 'files.lab,nas.lab,60', value: 'files.lab,nas.lab,60', aliases: ['files.lab'], target: 'nas.lab', ttl: 60, marks: [] });
		expect(writable(c)).toBe(true);
		expect(describeEntry(c)).toBe('files.lab → nas.lab, TTL 60s');
		expect(describeEntry(recordRow({ key: 'k', value: '10.0.0.5 nas', ip: '10.0.0.5', hostnames: ['nas'], marks: [] }))).toBe('nas (10.0.0.5)');
		// An unparsed entry is named by its string.
		expect(recordRow({ key: 'garbage', value: 'garbage', hostnames: [], marks: ['unparsed'] }).name).toBe('garbage');
	});
});

describe('instances', () => {
	const inst = (o: Partial<LocalDNSInstance>): LocalDNSInstance => ({
		instance: 'pihole1',
		instance_id: 1,
		writable: 'ok',
		records_locked: false,
		cnames_locked: false,
		...o
	});
	it('says what an instance the app can not change needs', () => {
		expect(writableProblem(inst({}))).toBeNull();
		expect(writableProblem(inst({ writable: 'app_sudo_off' }))).toMatch(/pihole-FTL --config webserver\.api\.app_sudo true/);
		expect(writableProblem(inst({ writable: 'locked' }))).toMatch(/read-only/);
		expect(writableProblem(inst({ cnames_locked: true }))).toMatch(/CNAMEs are set by an environment variable/);
	});
	it('offers changes only where they can work', () => {
		expect(canChange({ instances: [inst({})] }, 'record')).toBe(true);
		expect(canChange({ instances: [inst({ writable: 'app_sudo_off' })] }, 'record')).toBe(false);
		expect(canChange({ instances: [inst({ records_locked: true })] }, 'record')).toBe(false);
		expect(canChange({ instances: [inst({ records_locked: true })] }, 'cname')).toBe(true);
		// Through a mirrored group each member answers for itself.
		expect(canChange({ instances: [inst({ writable: 'app_sudo_off' })], members: [] }, 'record')).toBe(true);
	});
});

describe('directoryConfirmation', () => {
	it('reads the domain from the 409', () => {
		const e = new ApiError(409, 'confirmation_required', 'Confirm', { domain: 'corp.example', field: 'hostname' });
		expect(directoryConfirmation(e)).toEqual({ domain: 'corp.example', field: 'hostname' });
		expect(directoryConfirmation(new ApiError(409, 'conflict', 'No'))).toBeNull();
		expect(directoryConfirmation(new Error('x'))).toBeNull();
	});
});
