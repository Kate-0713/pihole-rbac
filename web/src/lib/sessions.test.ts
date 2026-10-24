// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { describeAgent, formatMinutes, generalProblems } from './sessions.js';

describe('describeAgent', () => {
	it('names common browsers and systems', () => {
		const cases: [string, string][] = [
			['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', 'Chrome on Windows'],
			['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0', 'Edge on Windows'],
			['Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0', 'Firefox on Linux'],
			['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15', 'Safari on macOS'],
			['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile Safari/604.1', 'Safari on iOS'],
			['Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36', 'Chrome on Android'],
			['curl/8.10.1', 'curl'],
			['', 'Unknown browser']
		];
		for (const [ua, want] of cases) expect(describeAgent(ua)).toBe(want);
	});
});

describe('formatMinutes', () => {
	it('says durations in words', () => {
		expect(formatMinutes(45)).toBe('45 minutes');
		expect(formatMinutes(60)).toBe('1 hour');
		expect(formatMinutes(480)).toBe('8 hours');
		expect(formatMinutes(90)).toBe('1 hour 30 minutes');
		expect(formatMinutes(2880)).toBe('2 days');
		expect(formatMinutes(1)).toBe('1 minute');
		expect(formatMinutes(0)).toBe('');
		expect(formatMinutes(Number.NaN)).toBe('');
	});
});

describe('generalProblems', () => {
	it('accepts the defaults and the limits', () => {
		expect(generalProblems(480, 60)).toEqual({ lifetime: null, idle: null });
		expect(generalProblems(15, 5)).toEqual({ lifetime: null, idle: null });
		expect(generalProblems(43200, 1440)).toEqual({ lifetime: null, idle: null });
	});
	it('catches the server rules', () => {
		expect(generalProblems(10, 5).lifetime).not.toBeNull();
		expect(generalProblems(43201, 60).lifetime).not.toBeNull();
		expect(generalProblems(60, 4).idle).not.toBeNull();
		expect(generalProblems(60, 1441).idle).not.toBeNull();
		expect(generalProblems(30, 60).idle).toContain("can't be longer");
		expect(generalProblems(60.5, 30).lifetime).not.toBeNull();
	});
});
