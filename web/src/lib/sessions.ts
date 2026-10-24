// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The sessions and settings pages' helpers: a readable name for a browser, durations in words, and the general
// settings' rules. Plain TypeScript, so it is tested without a browser. The server checks every rule again.
import type { Schemas } from '#lib/api/client.js';

export type SessionInfo = Schemas['SessionInfo'];
export type SessionList = Schemas['SessionList'];
export type GeneralSettings = Schemas['GeneralSettings'];

// describeAgent turns a User-Agent header into "Firefox on Windows". It only needs to be good enough to tell a
// user's sessions apart; anything it doesn't recognise is "Unknown browser".
// The first pattern that matches wins, so the order matters: Edge and Opera also say Chrome, Chrome also says Safari,
// an iPhone also says "like Mac OS X", and Android also says Linux.
const browsers: [RegExp, string][] = [
	[/Edg\//, 'Edge'],
	[/OPR\//, 'Opera'],
	[/Firefox\//, 'Firefox'],
	[/Chrome\//, 'Chrome'],
	[/Safari\//, 'Safari'],
	[/curl\//i, 'curl']
];
const systems: [RegExp, string][] = [
	[/Windows/, 'Windows'],
	[/Android/, 'Android'],
	[/iPhone|iPad|iPod/, 'iOS'],
	[/Mac OS X|Macintosh/, 'macOS'],
	[/Linux/, 'Linux']
];

export function describeAgent(ua: string): string {
	const browser = browsers.find(([re]) => re.test(ua))?.[1];
	const os = systems.find(([re]) => re.test(ua))?.[1];
	if (!browser && !os) return 'Unknown browser';
	if (!os) return browser!;
	return `${browser ?? 'A browser'} on ${os}`;
}

// formatMinutes says a duration in words: "45 minutes", "8 hours", "1 hour 30 minutes", "2 days".
export function formatMinutes(total: number): string {
	if (!Number.isFinite(total) || total <= 0) return '';
	const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'}`;
	const days = Math.floor(total / 1440);
	const hours = Math.floor((total % 1440) / 60);
	const minutes = total % 60;
	const parts: string[] = [];
	if (days) parts.push(plural(days, 'day'));
	if (hours) parts.push(plural(hours, 'hour'));
	if (minutes) parts.push(plural(minutes, 'minute'));
	return parts.join(' ');
}

// The general settings' ranges, as the server has them.
export const lifetimeRange = { min: 15, max: 30 * 24 * 60 };
export const idleRange = { min: 5, max: 24 * 60 };

// generalProblems returns a hint per field, or null where the field is fine.
export function generalProblems(lifetime: number, idle: number): { lifetime: string | null; idle: string | null } {
	const whole = (n: number) => Number.isInteger(n);
	const lifetimeProblem =
		!whole(lifetime) || lifetime < lifetimeRange.min || lifetime > lifetimeRange.max
			? `Use ${lifetimeRange.min} minutes to ${lifetimeRange.max} minutes (30 days).`
			: null;
	let idleProblem: string | null = null;
	if (!whole(idle) || idle < idleRange.min || idle > idleRange.max) {
		idleProblem = `Use ${idleRange.min} to ${idleRange.max} minutes (24 hours).`;
	} else if (lifetimeProblem === null && idle > lifetime) {
		idleProblem = "The idle timeout can't be longer than the session lifetime.";
	}
	return { lifetime: lifetimeProblem, idle: idleProblem };
}
