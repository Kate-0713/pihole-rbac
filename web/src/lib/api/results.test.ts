// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from './client.js';
import { failedResults, summarise, type InstanceResult } from './results.js';

const ok: InstanceResult = { instance: 'pihole1', instance_id: 1, status: 'ok' };
const failed: InstanceResult = {
	instance: 'pihole2',
	instance_id: 2,
	status: 'failed',
	error: { code: 'pihole_rejected', message: 'Refused.', pihole_message: 'UNIQUE constraint failed' }
};
const skipped: InstanceResult = {
	instance: 'pihole3',
	instance_id: 3,
	status: 'skipped',
	error: { code: 'pihole_unreachable', message: "Didn't respond." }
};

describe('summarise', () => {
	it('splits results by status', () => {
		const s = summarise([ok, failed, skipped]);
		expect(s.ok).toEqual([ok]);
		expect(s.failed).toEqual([failed]);
		expect(s.skipped).toEqual([skipped]);
		expect(s.allOk).toBe(false);
	});

	it('is all ok only when every result is, and there is at least one', () => {
		expect(summarise([ok]).allOk).toBe(true);
		expect(summarise([]).allOk).toBe(false);
	});

	it("keeps each operation's own fields", () => {
		const withEntry = { ...ok, entry: { domain: 'ads.example' } };
		expect(summarise([withEntry]).ok[0].entry.domain).toBe('ads.example');
	});
});

describe('failedResults', () => {
	it("reads a failed write's results from the error details", () => {
		const e = new ApiError(400, 'pihole_rejected', 'Refused.', { instance: 'pihole2', results: [failed, skipped] });
		expect(failedResults(e)).toEqual([failed, skipped]);
	});

	it('drops entries that aren\'t results, since details are untyped', () => {
		const e = new ApiError(502, 'pihole_unreachable', 'Down.', {
			results: [skipped, { instance: 'x' }, null, 'nonsense', { ...ok, status: 'maybe' }]
		});
		expect(failedResults(e)).toEqual([skipped]);
	});

	it('is null for errors without results, and for anything that isn\'t an ApiError', () => {
		expect(failedResults(new ApiError(404, 'not_found', 'Gone.'))).toBeNull();
		expect(failedResults(new ApiError(400, 'validation_failed', 'Bad.', { results: 'nope' }))).toBeNull();
		expect(failedResults(new Error('boom'))).toBeNull();
		expect(failedResults(undefined)).toBeNull();
	});
});
