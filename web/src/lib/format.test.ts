// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { formatCount, formatCountdown, formatDuration, formatPercent } from './format.js';

describe('formatCount and formatPercent', () => {
	it('use the locale given', () => {
		expect(formatCount(123456, 'en-GB')).toBe('123,456');
		expect(formatCount(123456, 'de-DE')).toBe('123.456');
		expect(formatPercent(25, 'en-GB')).toBe('25.0%');
		expect(formatPercent(12.345, 'en-GB')).toBe('12.3%');
		expect(formatPercent(0, 'en-GB')).toBe('0.0%');
	});
});

describe('formatCountdown', () => {
	it.each([
		[0, '0s'],
		[-3, '0s'],
		[0.2, '1s'], // rounds up, so it never shows 0s while time is left
		[45, '45s'],
		[60, '1:00'],
		[245, '4:05'],
		[3599, '59:59'],
		[3600, '1:00:00'],
		[86400, '24:00:00']
	])('%d seconds is %s', (seconds, want) => {
		expect(formatCountdown(seconds)).toBe(want);
	});
});

describe('formatDuration', () => {
	it.each([
		[1, '1 second'],
		[30, '30 seconds'],
		[60, '1 minute'],
		[300, '5 minutes'],
		[90, '90 seconds'],
		[3600, '1 hour'],
		[7200, '2 hours']
	])('%d seconds is %s', (seconds, want) => {
		expect(formatDuration(seconds)).toBe(want);
	});
});
