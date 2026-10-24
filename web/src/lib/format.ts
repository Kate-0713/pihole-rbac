// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Number and time formatting for display, in the browser's locale.

// formatCount groups digits as the browser's locale does: 123456 is "123,456" in English.
export function formatCount(n: number, locale?: string): string {
	return new Intl.NumberFormat(locale).format(n);
}

// formatPercent shows one decimal place: 25 is "25.0%". Pi-hole sends percentages as 0 to 100.
export function formatPercent(p: number, locale?: string): string {
	return new Intl.NumberFormat(locale, {
		style: 'percent',
		minimumFractionDigits: 1,
		maximumFractionDigits: 1
	}).format(p / 100);
}

// formatCountdown shows whole seconds left as "45s", "4:05" or "1:00:00". Negative values count as zero.
export function formatCountdown(seconds: number): string {
	const s = Math.max(0, Math.ceil(seconds));
	if (s < 60) return `${s}s`;
	const h = Math.floor(s / 3600);
	const m = Math.floor((s % 3600) / 60);
	const rest = String(s % 60).padStart(2, '0');
	return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${rest}` : `${m}:${rest}`;
}

// formatDuration names a length of time in words, for messages: 30 is "30 seconds", 300 "5 minutes", 3600 "1 hour".
export function formatDuration(seconds: number): string {
	const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
	if (seconds % 3600 === 0) return unit(seconds / 3600, 'hour');
	if (seconds % 60 === 0) return unit(seconds / 60, 'minute');
	return unit(seconds, 'second');
}

// formatDateTime shows an RFC 3339 time from the API as a short date and time in the browser's locale and time zone:
// "24/10/2026, 14:05" in British English. An empty or unparsable value is shown as an em dash.
export function formatDateTime(rfc3339: string | null | undefined, locale?: string, timeZone?: string): string {
	if (!rfc3339) return '—';
	const d = new Date(rfc3339);
	if (Number.isNaN(d.getTime())) return '—';
	return new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short', timeZone }).format(d);
}
