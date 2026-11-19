// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	caFileProblem,
	defaultPort,
	describeStatus,
	errorText,
	formInput,
	guardWarnings,
	hostProblem,
	moved,
	nameProblem,
	needsPlainConfirm,
	portProblem,
	toInput,
	where,
	type DestinationForm,
	type LogDestination
} from './logdestinations.js';

const dest: LogDestination = {
	id: 1,
	name: 'Graylog',
	host: 'logs.example.com',
	port: 6514,
	transport: 'tls',
	tls_mode: 'verify',
	enabled: true,
	created_at: '2026-11-18T12:00:00Z',
	created_by: 'admin',
	updated_at: '2026-11-18T12:00:00Z',
	updated_by: 'admin',
	status: { state: 'ok', behind: 0, delivery: 'at_least_once', last_sent_at: '2026-11-18T12:05:00Z' }
};

const form = (d: LogDestination, changes: Partial<DestinationForm> = {}): DestinationForm => ({
	host: d.host,
	port: String(d.port),
	transport: d.transport,
	tlsMode: d.tls_mode,
	caFile: d.ca_file ?? '',
	enabled: d.enabled,
	...changes
});

describe('field rules', () => {
	it('names', () => {
		expect(nameProblem('Graylog')).toBeNull();
		expect(nameProblem('  ')).not.toBeNull();
		expect(nameProblem('x'.repeat(81))).not.toBeNull();
		expect(nameProblem('a\u0007b')).not.toBeNull();
	});

	it('hosts are names or addresses', () => {
		for (const ok of ['logs.example.com', 'logs', '10.0.0.5', 'fd00::1', '::1', 'my_host.lan']) expect(hostProblem(ok), ok).toBeNull();
		for (const bad of ['', 'https://logs', 'logs:514', 'logs example', '-logs', 'logs..lan', 'a'.repeat(254), '[::1]']) {
			expect(hostProblem(bad), bad).not.toBeNull();
		}
	});

	it('ports', () => {
		expect(portProblem('514')).toBeNull();
		expect(portProblem('65535')).toBeNull();
		for (const bad of ['', '0', '65536', '-1', '5x', '1.5']) expect(portProblem(bad), bad).not.toBeNull();
	});

	it('CA file paths', () => {
		expect(caFileProblem('')).toBeNull();
		expect(caFileProblem('/etc/ssl/ca.pem')).toBeNull();
		expect(caFileProblem('C:\\certs\\ca.pem')).toBeNull();
		expect(caFileProblem('ca.pem')).not.toBeNull();
		expect(caFileProblem('/' + 'x'.repeat(4096))).not.toBeNull();
	});

	it('default ports', () => {
		expect(defaultPort('tls')).toBe(6514);
		expect(defaultPort('tcp')).toBe(514);
		expect(defaultPort('udp')).toBe(514);
	});
});

describe('the server’s rules, mirrored', () => {
	it('plain transports need a confirmation when new or changed to', () => {
		expect(needsPlainConfirm(null, 'tls')).toBe(false);
		expect(needsPlainConfirm(null, 'tcp')).toBe(true);
		expect(needsPlainConfirm(dest, 'udp')).toBe(true);
		expect(needsPlainConfirm({ ...dest, transport: 'tcp' }, 'tcp')).toBe(false);
		expect(needsPlainConfirm({ ...dest, transport: 'tcp' }, 'udp')).toBe(true);
	});

	it('moved means the address or how it is reached changed', () => {
		expect(moved(dest, form(dest))).toBe(false);
		expect(moved(dest, form(dest, { host: ' logs.example.com ' }))).toBe(false);
		expect(moved(dest, form(dest, { host: 'other.example.com' }))).toBe(true);
		expect(moved(dest, form(dest, { port: '6515' }))).toBe(true);
		expect(moved(dest, form(dest, { transport: 'tcp' }))).toBe(true);
		expect(moved(dest, form(dest, { tlsMode: 'insecure' }))).toBe(true);
		expect(moved(dest, form(dest, { caFile: '/etc/ca.pem' }))).toBe(true);
		// A CA file typed and then set aside by insecure isn't saved, so it isn't a move on its own.
		const plain = { ...dest, transport: 'tcp' as const };
		expect(moved(plain, form(plain, { tlsMode: 'insecure', caFile: '/x' }))).toBe(false);
	});

	it('warns the old place, only when it was sending', () => {
		expect(guardWarnings(null, form(dest))).toEqual([]);
		expect(guardWarnings({ ...dest, enabled: false }, form(dest, { host: 'x' }))).toEqual([]);
		expect(guardWarnings(dest, form(dest))).toEqual([]);
		expect(guardWarnings(dest, form(dest, { host: 'x' }))).toEqual(['the log now goes somewhere else']);
		expect(guardWarnings(dest, form(dest, { enabled: false }))).toEqual(['it was disabled']);
		expect(guardWarnings(dest, form(dest, { host: 'x', enabled: false }))).toEqual(['the log now goes somewhere else', 'it was disabled']);
	});
});

describe('bodies', () => {
	it('a form becomes an input, dropping what the transport ignores', () => {
		expect(formInput(' Graylog ', form(dest, { host: ' logs.example.com ', caFile: ' /etc/ca.pem ' }))).toEqual({
			name: 'Graylog',
			host: 'logs.example.com',
			port: 6514,
			transport: 'tls',
			tls_mode: 'verify',
			ca_file: '/etc/ca.pem',
			enabled: true
		});
		const tcp = formInput('x', form(dest, { transport: 'tcp', tlsMode: 'insecure', caFile: '/etc/ca.pem' }));
		expect(tcp.tls_mode).toBe('verify');
		expect(tcp.ca_file).toBeUndefined();
		expect(formInput('x', form(dest, { tlsMode: 'insecure', caFile: '/etc/ca.pem' })).ca_file).toBeUndefined();
	});

	it('toInput saves a destination as it is', () => {
		expect(toInput({ ...dest, ca_file: '/etc/ca.pem' }, { enabled: false })).toEqual({
			name: 'Graylog',
			host: 'logs.example.com',
			port: 6514,
			transport: 'tls',
			tls_mode: 'verify',
			ca_file: '/etc/ca.pem',
			enabled: false
		});
	});
});

describe('summaries', () => {
	it('where brackets an IPv6 address', () => {
		expect(where(dest)).toBe('logs.example.com:6514');
		expect(where({ ...dest, host: 'fd00::1', port: 514 })).toBe('[fd00::1]:514');
	});

	it('error codes read as sentences, and an unknown one is generic', () => {
		expect(errorText('dial_failed')).toBe('couldn’t connect');
		expect(errorText('something_new')).toBe('sending failed');
		expect(errorText(undefined)).toBe('sending failed');
	});

	it('status lines: failing first, then what was sent and what is left', () => {
		const lines = describeStatus({
			...dest,
			status: {
				state: 'failing',
				behind: 1204,
				delivery: 'best_effort',
				failing_since: '2026-11-18T12:00:00Z',
				last_error: 'dial_failed',
				skipped_pruned: 3
			}
		});
		expect(lines.map((l) => l.text)).toEqual([
			expect.stringMatching(/^Failing since .*: couldn’t connect\.$/),
			'Nothing sent since the app started.',
			expect.stringMatching(/^1,204 entries still to send\.$|^1\.204 entries still to send\.$|^1 204 entries still to send\.$/),
			expect.stringMatching(/ deleted by the retention before they were sent\.$/),
			'UDP is best effort: nothing says whether a message arrived.'
		]);
		expect(lines.map((l) => l.problem)).toEqual([true, false, false, true, false]);
		expect(describeStatus({ ...dest, status: { state: 'disabled', behind: 1, delivery: 'at_least_once' } }).map((l) => l.text)).toEqual([
			'1 entry still to send.'
		]);
	});
});
