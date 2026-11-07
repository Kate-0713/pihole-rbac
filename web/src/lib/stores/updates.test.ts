// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { UpdateStatus, VersionInfo } from '#lib/system.js';
import { UpdatesStore } from './updates.svelte.js';

// A Storage that keeps values in memory, or throws on every call (as in a browser with site data blocked).
function memoryStorage(throws = false): Storage {
	const m = new Map<string, string>();
	const check = () => {
		if (throws) throw new DOMException('blocked', 'SecurityError');
	};
	return {
		get length() {
			return m.size;
		},
		clear: () => m.clear(),
		key: (i) => [...m.keys()][i] ?? null,
		getItem: (k) => (check(), m.get(k) ?? null),
		setItem: (k, v) => (check(), void m.set(k, v)),
		removeItem: (k) => void m.delete(k)
	};
}

const statusBody: UpdateStatus = {
	current_version: '2.0.0',
	development: false,
	install: 'lxc',
	check_enabled: true,
	update_available: false,
	can_request: true,
	requests: []
};

const versionBody: VersionInfo = {
	version: '2.0.0',
	commit: 'abc1234',
	build_date: '2026-11-07T00:00:00Z',
	development: false,
	latest: { version: 'v2.1.0', url: 'https://github.com/Kate-0713/pihole-rbac/releases/tag/v2.1.0' },
	update_available: true
};

describe('UpdatesStore', () => {
	it('remembers the dismissed release across page loads', () => {
		const storage = memoryStorage();
		const a = new UpdatesStore(storage);
		expect(a.dismissed).toBeNull();
		a.dismiss('v2.1.0');
		expect(a.dismissed).toBe('v2.1.0');
		expect(new UpdatesStore(storage).dismissed).toBe('v2.1.0');
	});

	it('still dismisses when storage is blocked', () => {
		const s = new UpdatesStore(memoryStorage(true));
		expect(s.dismissed).toBeNull();
		s.dismiss('v2.1.0');
		expect(s.dismissed).toBe('v2.1.0');
	});

	it('reads the status once per user', async () => {
		let calls = 0;
		const s = new UpdatesStore(memoryStorage(), async () => (calls++, statusBody));
		await s.ensure(1, true);
		await s.ensure(1, true);
		expect(calls).toBe(1);
		expect(s.status?.current_version).toBe('2.0.0');
		await s.ensure(2, true);
		expect(calls).toBe(2);
		s.reset();
		expect(s.status).toBeNull();
		expect(s.banner).toBeNull();
		await s.ensure(2, true);
		expect(calls).toBe(3);
	});

	it("shows nothing when the status can't be read", async () => {
		const s = new UpdatesStore(memoryStorage(), async () => {
			throw new Error('forbidden');
		});
		await s.ensure(1, true);
		expect(s.status).toBeNull();
		expect(s.banner).toBeNull();
	});

	it('gives the banner the full status to people who can update', async () => {
		let versionCalls = 0;
		const s = new UpdatesStore(
			memoryStorage(),
			async () => ({ ...statusBody, update_available: true, latest: versionBody.latest }),
			async () => (versionCalls++, versionBody)
		);
		await s.ensure(1, true);
		expect(versionCalls).toBe(0);
		expect(s.status?.install).toBe('lxc');
		expect(s.banner).toEqual({
			current_version: '2.0.0',
			development: false,
			latest: versionBody.latest,
			update_available: true
		});
	});

	it('gives everyone else only the version endpoint', async () => {
		let statusCalls = 0;
		const s = new UpdatesStore(
			memoryStorage(),
			async () => (statusCalls++, statusBody),
			async () => versionBody
		);
		await s.ensure(1, false);
		expect(statusCalls).toBe(0);
		expect(s.status).toBeNull();
		expect(s.banner).toEqual({
			current_version: '2.0.0',
			development: false,
			latest: versionBody.latest,
			update_available: true
		});
		// Gaining app.update later reads the full status.
		await s.ensure(1, true);
		expect(statusCalls).toBe(1);
		expect(s.status).not.toBeNull();
	});

	it('treats a version answer without a release as no update', async () => {
		const s = new UpdatesStore(memoryStorage(), async () => statusBody, async () => ({
			version: 'dev',
			commit: 'unknown',
			build_date: 'unknown',
			development: true
		}));
		await s.ensure(1, false);
		expect(s.banner?.update_available).toBe(false);
		expect(s.banner?.latest).toBeUndefined();
	});
});
