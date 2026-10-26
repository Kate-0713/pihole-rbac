// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	activeRequest,
	bannerVersion,
	describeReload,
	describeSource,
	displayVersion,
	finishedOutcome,
	requestTarget,
	targetProblem,
	type UpdateRequest,
	type UpdateStatus
} from './system.js';

const request = (id: number, status: UpdateRequest['status'], target?: string): UpdateRequest => ({
	id,
	requested_at: '2026-10-26T12:00:00Z',
	requested_by: 'admin',
	status,
	log: '',
	...(target ? { target_version: target } : {})
});

const status = (over: Partial<UpdateStatus> = {}): UpdateStatus => ({
	current_version: '2.0.0',
	development: false,
	install: 'lxc',
	check_enabled: true,
	update_available: true,
	can_request: true,
	latest: { version: 'v2.1.0', url: 'https://github.com/Kate-0713/pihole-rbac/releases/tag/v2.1.0' },
	requests: [],
	...over
});

describe('displayVersion', () => {
	it('adds the v to a release build', () => {
		expect(displayVersion('2.1.0', false)).toBe('v2.1.0');
		expect(displayVersion('2.1.0-rc.1', false)).toBe('v2.1.0-rc.1');
		expect(displayVersion('v2.1.0', false)).toBe('v2.1.0');
	});
	it('leaves a development build alone', () => {
		expect(displayVersion('dev', true)).toBe('dev');
		expect(displayVersion('v2.0.0-3-gabc1234', true)).toBe('v2.0.0-3-gabc1234');
	});
});

describe('targetProblem', () => {
	it('accepts empty, release and prerelease tags', () => {
		for (const t of ['', '  ', 'v2.1.0', ' v2.1.0 ', 'v2.1.0-rc.1', 'v10.0.0-beta']) expect(targetProblem(t)).toBeNull();
	});
	it('refuses anything else, as the server does', () => {
		for (const t of ['2.1.0', 'latest', 'v2.1', 'v02.1.0', 'v2.1.0-', 'v2.1.0-rc..1', 'v2.1.0+build', 'v2.1.0/../x']) {
			expect(targetProblem(t), t).not.toBeNull();
		}
	});
});

describe('requests', () => {
	it('finds the one still pending or running', () => {
		expect(activeRequest(null)).toBeUndefined();
		expect(activeRequest(status({ requests: [request(3, 'done'), request(2, 'failed')] }))).toBeUndefined();
		expect(activeRequest(status({ requests: [request(4, 'running'), request(3, 'done')] }))?.id).toBe(4);
		expect(activeRequest(status({ requests: [request(5, 'pending')] }))?.id).toBe(5);
	});
	it('names the target', () => {
		expect(requestTarget(request(1, 'done'))).toBe('the latest release');
		expect(requestTarget(request(1, 'done', 'v2.1.0-rc.1'))).toBe('v2.1.0-rc.1');
	});
});

describe('bannerVersion', () => {
	it('shows a newer release until that version is dismissed', () => {
		expect(bannerVersion(status(), null)).toBe('v2.1.0');
		expect(bannerVersion(status(), 'v2.1.0')).toBeNull();
		expect(bannerVersion(status(), 'v2.0.5')).toBe('v2.1.0');
	});
	it('shows nothing without an update', () => {
		expect(bannerVersion(null, null)).toBeNull();
		expect(bannerVersion(status({ update_available: false }), null)).toBeNull();
		expect(bannerVersion(status({ latest: undefined }), null)).toBeNull();
	});
});

describe('secrets', () => {
	it('says where each came from', () => {
		expect(describeSource({ name: 'X', kind: 'master_key', set: false })).toBe('Not set');
		expect(describeSource({ name: 'X', kind: 'master_key', set: true, source: 'file' })).toMatch(/Reload secrets/);
		expect(describeSource({ name: 'X', kind: 'master_key', set: true, source: 'env' })).toMatch(/restart/);
		expect(describeSource({ name: 'X', kind: 'session_key', set: true, source: 'generated' })).toMatch(/Generated/);
	});
	it('sums up a reload', () => {
		expect(describeReload({ changed: [], failed: [], session_ended: false })).toBe('Secrets reloaded: nothing had changed.');
		expect(
			describeReload({
				changed: ['PIHOLE_RBAC_INSTANCE_A_PASSWORD'],
				failed: [{ name: 'PIHOLE_RBAC_LDAP_BIND_PASSWORD', message: 'no such file' }],
				session_ended: false
			})
		).toBe('Secrets reloaded (changed: PIHOLE_RBAC_INSTANCE_A_PASSWORD; failed: PIHOLE_RBAC_LDAP_BIND_PASSWORD).');
	});
});

describe('finishedOutcome', () => {
	it('reports the request that was in progress once it finishes', () => {
		const before = status({ requests: [request(2, 'running'), request(1, 'done')] });
		expect(finishedOutcome(before, status({ requests: [request(2, 'running')] }))).toBeNull();
		expect(finishedOutcome(before, status({ current_version: '2.1.0', requests: [request(2, 'done')] }))).toEqual({
			ok: true,
			message: 'Update finished: running v2.1.0.'
		});
		expect(finishedOutcome(before, status({ requests: [request(2, 'rolled_back')] }))?.ok).toBe(false);
		expect(finishedOutcome(before, status({ requests: [request(2, 'failed')] }))?.message).toMatch(/failed/);
	});
	it('says nothing when no request was in progress', () => {
		expect(finishedOutcome(null, status({ requests: [request(2, 'done')] }))).toBeNull();
		expect(finishedOutcome(status({ requests: [request(1, 'done')] }), status({ requests: [request(1, 'done')] }))).toBeNull();
	});
});
