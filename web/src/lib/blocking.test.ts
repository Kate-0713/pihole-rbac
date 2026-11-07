// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { durationProblem, maxBlockingTimer } from './blocking.js';

describe('durationProblem', () => {
	it.each([
		[0, 1],
		[0, 59],
		[1, 30],
		[23, 59],
		[24, 0],
		[null, 15],
		[2, null]
	])('%s h %s min can be sent', (h, m) => {
		expect(durationProblem(h, m)).toBeNull();
	});

	it.each([
		[0, 0, 'at least 1 minute'],
		[null, null, 'at least 1 minute'],
		[24, 1, 'at most 24 hours'],
		[25, 0, 'at most 24 hours'],
		[0, 60, 'up to 59'],
		[-1, 30, 'whole numbers'],
		[0, 1.5, 'whole numbers']
	])('%s h %s min is refused (%s)', (h, m, want) => {
		expect(durationProblem(h, m)).toContain(want);
	});

	it('matches the API limit', () => {
		expect(maxBlockingTimer).toBe(86400);
	});
});
