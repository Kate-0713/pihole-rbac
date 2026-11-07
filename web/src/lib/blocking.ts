// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The longest blocking timer the API accepts, in seconds: BlockingInput.timer's maximum in api/openapi.yaml and
// maxBlockingTimer in internal/api/targets.go. The server checks again.
export const maxBlockingTimer = 86400;

// durationProblem checks a custom "turn blocking off for" length given as hours and minutes, either of which may be
// null while its box is empty (treated as 0). It returns what's wrong, or null when the length can be sent.
export function durationProblem(hours: number | null, minutes: number | null): string | null {
	const h = hours ?? 0;
	const m = minutes ?? 0;
	if (!Number.isInteger(h) || !Number.isInteger(m) || h < 0 || m < 0) {
		return 'Use whole numbers of hours and minutes.';
	}
	if (m > 59) return 'Minutes go up to 59; use the hours box for longer.';
	const seconds = h * 3600 + m * 60;
	if (seconds < 60) return 'Turn it off for at least 1 minute.';
	if (seconds > maxBlockingTimer) return 'Blocking can be turned off for at most 24 hours at a time.';
	return null;
}
