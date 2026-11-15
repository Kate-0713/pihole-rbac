// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	addressProblem,
	formatDuration,
	listKey,
	memberProblems,
	mergeOutput,
	resultText,
	runSummary,
	waitingCount,
	type GravityRun,
	type PiholeList
} from './lists.js';

describe('addressProblem', () => {
	it('accepts http and https addresses with a host, ignoring surrounding spaces', () => {
		expect(addressProblem('https://lists.example/ads.txt')).toBeNull();
		expect(addressProblem('  http://lists.example/ads.txt ')).toBeNull();
		expect(addressProblem('HTTPS://lists.example:8443/l?key=a&b=c#top')).toBeNull();
		expect(addressProblem('https://[2001:db8::1]/ads.txt')).toBeNull();
		expect(addressProblem('https://lists.example/user@example.txt')).toBeNull(); // an @ in the path isn't a login
	});

	it('refuses what the server refuses', () => {
		expect(addressProblem('')).toMatch(/Enter/);
		expect(addressProblem('https://lists.example/a b')).toMatch(/spaces/);
		expect(addressProblem('https://lists.example/a\tb')).toMatch(/spaces/);
		expect(addressProblem('https://lists.example/\u0007')).toMatch(/control/);
		expect(addressProblem('https://lists.example/' + 'a'.repeat(2048))).toMatch(/2048 bytes/);
		expect(addressProblem('https://user:pw@lists.example/ads.txt')).toMatch(/user name and password/);
		expect(addressProblem('https://token@lists.example/ads.txt')).toMatch(/user name and password/);
		expect(addressProblem('ftp://lists.example/ads.txt')).toMatch(/^ftp: addresses aren't allowed/);
		expect(addressProblem('sftp://host/ads.txt')).toMatch(/^sftp:/);
		expect(addressProblem('lists.example/ads.txt')).toMatch(/Start the address/);
		expect(addressProblem('https:///ads.txt')).not.toBeNull();
	});

	it('leaves file: to the setting', () => {
		expect(addressProblem('file:///etc/pihole/list.txt')).toMatch(/turned off/);
		expect(addressProblem('file:///etc/pihole/list.txt', true)).toBeNull();
		expect(addressProblem('file:/etc/pihole/list.txt', true)).toBeNull();
		expect(addressProblem('file://localhost/etc/pihole/list.txt', true)).toBeNull();
		expect(addressProblem('file:relative.txt', true)).toMatch(/absolute path/);
	});
});

const list = (over: Partial<PiholeList> = {}): PiholeList => ({
	address: 'https://lists.example/ads.txt',
	type: 'block',
	comment: '',
	groups: [0],
	enabled: true,
	status: 'updated',
	domains: 1000,
	invalid_domains: 0,
	needs_gravity: false,
	marks: [],
	...over
});

describe('lists', () => {
	it('keys a list by type and address', () => {
		expect(listKey(list())).toBe('block/https://lists.example/ads.txt');
		expect(listKey(list({ type: 'allow' }))).not.toBe(listKey(list()));
	});

	it('counts the lists waiting for gravity', () => {
		expect(waitingCount([list(), list({ needs_gravity: true }), list({ needs_gravity: true })])).toBe(2);
	});

	it('names the members whose copy needs a look', () => {
		expect(memberProblems(list())).toEqual([]);
		const l = list({
			members: [
				{ instance: 'alpha', instance_id: 1, primary: true, state: 'ok', status: 'updated' },
				{ instance: 'beta', instance_id: 2, primary: false, state: 'ok', status: 'cached' },
				{ instance: 'gamma', instance_id: 3, primary: false, state: 'missing' },
				{ instance: 'delta', instance_id: 4, primary: false, state: 'unreadable' },
				{ instance: 'eps', instance_id: 5, primary: false, state: 'ok', status: 'failed' }
			]
		});
		expect(memberProblems(l)).toEqual([
			'beta: download failed (old copy used)',
			'gamma: not subscribed',
			"delta: couldn't be read",
			'eps: download failed'
		]);
	});
});

const run = (over: Partial<GravityRun> = {}): GravityRun => ({
	id: 'a'.repeat(24),
	target: 'g-1',
	status: 'done',
	started_at: '2026-11-15T12:00:00Z',
	started_by: 'admin',
	results: [],
	output: [],
	output_last_seq: 0,
	output_truncated: false,
	...over
});

describe('gravity runs', () => {
	it('describes each result', () => {
		const base = { instance: 'alpha', instance_id: 1, primary: true };
		expect(resultText({ ...base, status: 'pending' })).toMatch(/Waiting/);
		expect(resultText({ ...base, status: 'ok', domains: 123456, duration_ms: 65000, lists_failed: 2 })).toBe(
			`Done: ${(123456).toLocaleString()} domains in 1m 5s. 2 lists failed to download.`
		);
		expect(resultText({ ...base, status: 'failed', error: { code: 'gravity_failed', message: 'Gravity failed.' } })).toBe(
			'Gravity failed.'
		);
		expect(resultText({ ...base, status: 'skipped', reason: 'stopped' })).toMatch(/earlier member failed/);
		expect(resultText({ ...base, status: 'skipped', reason: 'down' })).toMatch(/couldn't be reached/);
		expect(formatDuration(400)).toBe('under a second');
		expect(formatDuration(42_000)).toBe('42s');
	});

	it('sums a run up', () => {
		const ok = (instance: string) => ({ instance, instance_id: 1, primary: false, status: 'ok' as const });
		expect(runSummary(run({ results: [ok('alpha'), ok('beta')] }))).toEqual({
			ok: true,
			text: 'Gravity updated on alpha and beta.'
		});
		const s = runSummary(
			run({
				results: [
					ok('alpha'),
					{ instance: 'beta', instance_id: 2, primary: false, status: 'failed' },
					{ instance: 'gamma', instance_id: 3, primary: false, status: 'skipped', reason: 'stopped' }
				]
			})
		);
		expect(s).toEqual({ ok: false, text: 'Gravity updated on alpha; failed on beta; skipped on gamma.' });
	});

	it('merges output without repeats, marking a gap', () => {
		const line = (seq: number) => ({ seq, instance_id: 1, text: `line ${seq}` });
		let shown = mergeOutput([], run({ output: [line(1), line(2)] }));
		expect(shown.map((l) => l.seq)).toEqual([1, 2]);
		// A poll can return lines already shown; only newer ones are added.
		shown = mergeOutput(shown, run({ output: [line(2), line(3)] }));
		expect(shown.map((l) => l.seq)).toEqual([1, 2, 3]);
		shown = mergeOutput(shown, run({ output: [line(250)], output_truncated: true }));
		expect(shown.map((l) => l.seq)).toEqual([1, 2, 3, 0, 250]);
		// A first read that was truncated has nothing to mark a gap after.
		expect(mergeOutput([], run({ output: [line(9)], output_truncated: true })).map((l) => l.seq)).toEqual([9]);
	});
});
