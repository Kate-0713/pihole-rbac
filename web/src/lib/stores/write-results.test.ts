// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import type { InstanceResult } from '#lib/api/results.js';
import { reportFailure, reportResults } from '#lib/write-report.js';
import { notices } from './notices.svelte.js';
import { mergeResults, toRetry, writeResults } from './write-results.svelte.js';

const text = { done: 'games.example added to the deny list', failed: "Couldn't add games.example" };
const ok = (instance: string, instance_id: number): InstanceResult => ({ instance, instance_id, status: 'ok' });
const failed = (instance: string, instance_id: number, code = 'pihole_unreachable'): InstanceResult => ({
	instance,
	instance_id,
	status: 'failed',
	error: { code, message: `Pi-hole "${instance}" didn't respond.` }
});
const skipped = (instance: string, instance_id: number): InstanceResult => ({
	instance,
	instance_id,
	status: 'skipped',
	error: { code: 'pihole_unreachable', message: `Pi-hole "${instance}" didn't respond.` }
});

let success: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
	success = vi.spyOn(notices, 'success').mockImplementation(() => {});
	notices.clear();
	writeResults.dismiss();
});
afterEach(() => vi.restoreAllMocks());

describe('mergeResults and toRetry', () => {
	it('retries what failed or was skipped, and puts the new results in place', () => {
		const before = [ok('alpha', 1), failed('beta', 2), skipped('gamma', 3)];
		expect(toRetry(before)).toEqual([2, 3]);
		expect(mergeResults(before, [ok('gamma', 3)]).map((r) => r.status)).toEqual(['ok', 'failed', 'ok']);
	});
});

describe('reportResults with a retry', () => {
	it('opens the panel for a group write that partly failed, instead of toasts', () => {
		const retry = vi.fn();
		expect(reportResults([ok('alpha', 1), failed('beta', 2)], text, { retry })).toBe(false);
		expect(writeResults.panel?.results.map((r) => r.instance)).toEqual(['alpha', 'beta']);
		expect(success).not.toHaveBeenCalled();
		expect(notices.errors).toEqual([]);
	});

	it('is still a toast when every member worked, or for a single instance', () => {
		expect(reportResults([ok('alpha', 1), ok('beta', 2)], text, { retry: vi.fn() })).toBe(true);
		expect(success).toHaveBeenCalledWith('games.example added to the deny list on alpha and beta.');
		reportResults([failed('pihole1', 1)], text, { retry: vi.fn() });
		expect(writeResults.panel).toBeNull();
		expect(notices.errors).toHaveLength(1);
	});

	it('opens the panel for a group write where every member failed', () => {
		const e = new ApiError(502, 'pihole_unreachable', 'Pi-hole "alpha" didn\'t respond.', {
			results: [failed('alpha', 1), failed('beta', 2)]
		});
		reportFailure(e, text, { retry: vi.fn() });
		expect(writeResults.panel?.results).toHaveLength(2);
	});
});

describe('writeResults.retry', () => {
	it('sends the failed members, and closes with a toast once every member worked', async () => {
		const retry = vi.fn().mockResolvedValue([ok('beta', 2), ok('gamma', 3)]);
		const after = vi.fn();
		reportResults([ok('alpha', 1), failed('beta', 2), skipped('gamma', 3)], text, { retry, after });
		await writeResults.retry();
		expect(retry).toHaveBeenCalledWith([2, 3]);
		expect(writeResults.panel).toBeNull();
		expect(success).toHaveBeenCalledWith('games.example added to the deny list on every member.');
		expect(after).toHaveBeenCalled();
	});

	it('keeps the panel with the new results when a member still fails', async () => {
		const retry = vi.fn().mockResolvedValue([ok('beta', 2), failed('gamma', 3, 'pihole_status_error')]);
		reportResults([ok('alpha', 1), failed('beta', 2), failed('gamma', 3)], text, { retry });
		await writeResults.retry();
		expect(writeResults.panel?.results.map((r) => r.status)).toEqual(['ok', 'ok', 'failed']);
		expect(writeResults.panel?.results[2].error?.code).toBe('pihole_status_error');
	});

	it('takes the new errors from a retry that failed everywhere', async () => {
		const retry = vi
			.fn()
			.mockRejectedValue(
				new ApiError(409, 'pihole_group_missing', 'x', { results: [failed('gamma', 3, 'pihole_group_missing')] })
			);
		reportResults([ok('alpha', 1), failed('gamma', 3)], text, { retry });
		await writeResults.retry();
		expect(writeResults.panel?.results[1].error?.code).toBe('pihole_group_missing');
		expect(notices.errors).toEqual([]);
	});

	it('reports a retry that failed without results, and keeps the panel', async () => {
		const retry = vi.fn().mockRejectedValue(new ApiError(403, 'forbidden', 'You need domains.edit.', {}));
		reportResults([ok('alpha', 1), failed('gamma', 3)], text, { retry });
		await writeResults.retry();
		expect(writeResults.panel?.results[1].status).toBe('failed');
		expect(notices.errors[0].message).toBe("Couldn't add games.example: You need domains.edit.");
	});
});
