// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, describe, expect, it } from 'vitest';
import type { CurrentSession } from '#lib/stores/session.svelte.js';
import { session } from '#lib/stores/session.svelte.js';
import { can, canAny, canAnyGlobal } from './permissions.js';

// A session as GET /auth/session returns it. Only the permissions matter here.
function sessionWith(permissions: CurrentSession['permissions']): CurrentSession {
	return {
		user: { id: 1, username: 'alice', source: 'local' },
		csrf_token: 'token',
		expires_at: '2026-10-24T18:00:00Z',
		permissions
	} as CurrentSession;
}

afterEach(() => {
	session.current = null;
});

describe('can', () => {
	it('is false for everything without a session', () => {
		expect(can('users.manage')).toBe(false);
		expect(can('domains.view', 'i-1')).toBe(false);
		expect(canAny('i-1')).toBe(false);
	});

	it('looks global permissions up in global, and target permissions under their target', () => {
		session.current = sessionWith({
			global: ['audit.view'],
			targets: { 'i-1': ['domains.view', 'domains.edit'], 'g-2': ['drift.view'] }
		});
		expect(can('audit.view')).toBe(true);
		expect(can('users.manage')).toBe(false);
		expect(can('domains.edit', 'i-1')).toBe(true);
		expect(can('clients.view', 'i-1')).toBe(false);
		expect(can('domains.view', 'i-2')).toBe(false);
		expect(can('drift.view', 'g-2')).toBe(true);
	});

	it('never treats a target permission as global, or a missing target as any target', () => {
		session.current = sessionWith({ global: [], targets: { 'i-1': ['domains.view'] } });
		// Called without a target, a target permission is looked up among the global ones, where it never is.
		expect((can as (p: string) => boolean)('domains.view')).toBe(false);
		expect(can('domains.view', null)).toBe(false);
	});
});

describe('canAny and canAnyGlobal', () => {
	it('canAny needs at least one permission on that target', () => {
		session.current = sessionWith({ global: [], targets: { 'i-1': ['querylog.view'], 'i-2': [] } });
		expect(canAny('i-1')).toBe(true);
		expect(canAny('i-2')).toBe(false);
		expect(canAny('i-3')).toBe(false);
		expect(canAny(undefined)).toBe(false);
		expect(canAny('')).toBe(false);
	});

	it('canAnyGlobal needs one of the listed permissions', () => {
		session.current = sessionWith({ global: ['sessions.manage'], targets: {} });
		expect(canAnyGlobal('users.manage', 'sessions.manage')).toBe(true);
		expect(canAnyGlobal('users.manage', 'roles.manage')).toBe(false);
		expect(canAnyGlobal()).toBe(false);
	});
});
