// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import type { UpdateStatus } from '#lib/system.js';
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
		await s.ensure(1);
		await s.ensure(1);
		expect(calls).toBe(1);
		expect(s.status?.current_version).toBe('2.0.0');
		await s.ensure(2);
		expect(calls).toBe(2);
		s.reset();
		expect(s.status).toBeNull();
		await s.ensure(2);
		expect(calls).toBe(3);
	});

	it("shows nothing when the status can't be read", async () => {
		const s = new UpdatesStore(memoryStorage(), async () => {
			throw new Error('forbidden');
		});
		await s.ensure(1);
		expect(s.status).toBeNull();
	});
});
