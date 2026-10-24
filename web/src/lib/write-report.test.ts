// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import type { InstanceResult } from '#lib/api/results.js';
import { notices } from '#lib/stores/notices.svelte.js';
import { reportFailure, reportResults } from './write-report.js';

const text = { done: 'Blocking turned off', failed: "Couldn't turn blocking off" };
const ok = (instance: string): InstanceResult => ({ instance, instance_id: 1, status: 'ok' });
const failed: InstanceResult = {
	instance: 'pihole2',
	instance_id: 2,
	status: 'failed',
	error: { code: 'pihole_rejected', message: 'Pi-hole "pihole2" refused the request.' }
};
const skipped: InstanceResult = {
	instance: 'pihole3',
	instance_id: 3,
	status: 'skipped',
	error: { code: 'pihole_unreachable', message: 'Pi-hole "pihole3" didn\'t respond.' }
};

let success: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
	// The toast itself needs a page to show on; what matters here is what it's asked to say.
	success = vi.spyOn(notices, 'success').mockImplementation(() => {});
	notices.clear();
});
afterEach(() => vi.restoreAllMocks());

describe('reportResults', () => {
	it('is one success toast naming the instance when it succeeded', () => {
		expect(reportResults([ok('pihole1')], text)).toBe(true);
		expect(success).toHaveBeenCalledWith('Blocking turned off on pihole1.');
		expect(notices.errors).toEqual([]);
	});

	it('names every instance that succeeded', () => {
		reportResults([ok('a'), ok('b'), ok('c')], text);
		expect(success).toHaveBeenCalledWith('Blocking turned off on a, b and c.');
	});

	it('shows each failure on its own, and the successes, when results differ', () => {
		expect(reportResults([ok('pihole1'), failed, skipped], text)).toBe(false);
		expect(success).toHaveBeenCalledWith('Blocking turned off on pihole1.');
		expect(notices.errors.map((n) => n.message)).toEqual([
			`Couldn't turn blocking off: Pi-hole "pihole3" didn't respond.`,
			`Couldn't turn blocking off: Pi-hole "pihole2" refused the request.`
		]);
	});
});

describe('reportFailure', () => {
	it("shows each instance's error when the failure carries results", () => {
		reportFailure(new ApiError(400, 'pihole_rejected', 'Refused.', { results: [failed] }), text);
		expect(success).not.toHaveBeenCalled();
		expect(notices.errors.map((n) => n.message)).toEqual([
			`Couldn't turn blocking off: Pi-hole "pihole2" refused the request.`
		]);
	});

	it("shows the server's message for a refusal without results", () => {
		reportFailure(new ApiError(403, 'forbidden', "You don't have permission."), text);
		expect(notices.errors.map((n) => n.message)).toEqual(["Couldn't turn blocking off: You don't have permission."]);
	});
});
