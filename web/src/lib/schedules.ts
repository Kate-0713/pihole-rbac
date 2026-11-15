// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Schemas } from '#lib/api/client.js';
import { isTimeZone, timePattern, zoneOffset } from '#lib/clientreset.js';

export type Schedule = Schemas['Schedule'];
export type ScheduleList = Schemas['ScheduleList'];
export type ScheduleInput = Schemas['ScheduleInput'];
export type ScheduleKind = Schemas['ScheduleKind'];
export type ScheduleResult = Schemas['ScheduleResult'];
export type ScheduleStatus = Schemas['ScheduleStatus'];
export type ScheduleStatusItem = Schemas['ScheduleStatusItem'];

// The days of the week as the API's bits, Monday first.
export const days = [
	{ bit: 1, short: 'Mon', long: 'Monday' },
	{ bit: 2, short: 'Tue', long: 'Tuesday' },
	{ bit: 4, short: 'Wed', long: 'Wednesday' },
	{ bit: 8, short: 'Thu', long: 'Thursday' },
	{ bit: 16, short: 'Fri', long: 'Friday' },
	{ bit: 32, short: 'Sat', long: 'Saturday' },
	{ bit: 64, short: 'Sun', long: 'Sunday' }
] as const;
export const allDays = 127;
export const weekdays = 31;
export const weekends = 96;

// The limits, as the server has them: a blocking window is Pi-hole's 24-hour timer at most, a weekly window repeats
// every week, and a group window has the admin's maximum.
export const maxBlockingMinutes = 24 * 60;
export const maxWeeklyMinutes = 7 * 24 * 60;

export const kindLabel: Record<ScheduleKind, string> = {
	blocking_off: 'Blocking off',
	group_enabled: 'Group on',
	group_disabled: 'Group off'
};

// describeDays names a set of days: "Every day", "Weekdays", "Weekends", or "Mon, Wed, Fri".
export function describeDays(bits: number): string {
	if (bits === allDays) return 'Every day';
	if (bits === weekdays) return 'Weekdays';
	if (bits === weekends) return 'Weekends';
	return days
		.filter((d) => bits & d.bit)
		.map((d) => d.short)
		.join(', ');
}

// endsWhen says when a weekly window ends, relative to its start day: "07:00 the next day", "07:00 3 days later".
function endsWhen(end: string, endDays: number): string {
	if (endDays === 0) return end;
	if (endDays === 1) return `${end} the next day`;
	return `${end}, ${endDays} days later`;
}

// describeWhen says when a schedule's windows happen, in its own zone for a weekly one: "Weekdays 08:00–08:30",
// "Every day 21:00 to 07:00 the next day". A one-off window is shown with format, in the browser's zone by default.
export function describeWhen(s: Schedule, format: (iso: string) => string): string {
	if (s.repeat === 'once') return `${format(s.starts_at ?? '')} to ${format(s.ends_at ?? '')}`;
	const ed = s.end_days ?? 0;
	const when = `${describeDays(s.days ?? 0)} ${s.start}`;
	return ed === 0 ? `${when}–${s.end}` : `${when} to ${endsWhen(s.end ?? '', ed)}`;
}

// lengthText names a length in minutes: "30 minutes", "10 hours", "1 day 12 hours".
export function lengthText(minutes: number): string {
	const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
	if (minutes === 24 * 60) return '24 hours';
	const d = Math.floor(minutes / (24 * 60));
	const h = Math.floor((minutes % (24 * 60)) / 60);
	const m = minutes % 60;
	const parts: string[] = [];
	if (d > 0) parts.push(unit(d, 'day'));
	if (h > 0) parts.push(unit(h, 'hour'));
	if (m > 0 || parts.length === 0) parts.push(unit(m, 'minute'));
	return parts.join(' ');
}

const clock = (hhmm: string) => {
	const [h, m] = hhmm.split(':').map(Number);
	return h * 60 + m;
};

// The form: what the dialog edits, as text and numbers, before it becomes a request.
export type Form = {
	name: string;
	kind: ScheduleKind;
	group: string;
	repeat: 'weekly' | 'once';
	enabled: boolean;
	days: number;
	start: string;
	end: string;
	endDays: number;
	zone: string;
	// A one-off window, as a local date and time in zone.
	startDate: string;
	startTime: string;
	endDate: string;
	endTime: string;
};

// nominalMinutes is the weekly window's length as entered, as the server works it out.
export function nominalMinutes(f: Pick<Form, 'start' | 'end' | 'endDays'>): number {
	if (!timePattern.test(f.start) || !timePattern.test(f.end)) return Number.NaN;
	return f.endDays * 24 * 60 + clock(f.end) - clock(f.start);
}

// shortestGapMinutes is the shortest time from one selected day to the next, a week when only one is selected.
export function shortestGapMinutes(bits: number): number {
	const sel = days.map((d, i) => (bits & d.bit ? i : -1)).filter((i) => i >= 0);
	if (sel.length === 0) return 0;
	let gap = 7;
	sel.forEach((d, i) => {
		const g = (sel[(i + 1) % sel.length] - d + 7) % 7 || 7;
		gap = Math.min(gap, g);
	});
	return gap * 24 * 60;
}

// suggestEndDays is the end day a weekly window most likely means: the next day when it ends at or before its start.
export function suggestEndDays(start: string, end: string): number {
	if (!timePattern.test(start) || !timePattern.test(end)) return 0;
	return clock(end) <= clock(start) ? 1 : 0;
}

// zonedToDate is the instant a wall-clock date and time ("2027-03-01", "08:00") is in a zone. A time the clocks skip
// comes out an hour later, as the server's time.Date does.
export function zonedToDate(date: string, time: string, zone: string): Date | null {
	const dm = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
	if (!dm || !timePattern.test(time) || !isTimeZone(zone)) return null;
	const [h, min] = time.split(':').map(Number);
	const wall = Date.UTC(Number(dm[1]), Number(dm[2]) - 1, Number(dm[3]), h, min);
	let at = wall - zoneOffset(wall, zone);
	at = wall - zoneOffset(at, zone);
	return new Date(at);
}

// dateToZoned is the wall-clock date and time of an instant in a zone, for filling the form from a saved schedule.
export function dateToZoned(iso: string, zone: string): { date: string; time: string } {
	const at = new Date(iso).getTime();
	const local = new Date(at + zoneOffset(at, zone));
	const p = (n: number) => String(n).padStart(2, '0');
	return {
		date: `${local.getUTCFullYear()}-${p(local.getUTCMonth() + 1)}-${p(local.getUTCDate())}`,
		time: `${p(local.getUTCHours())}:${p(local.getUTCMinutes())}`
	};
}

// maxMinutes is the longest the form's window can be, given the group window limit the server reported.
export function maxMinutes(f: Pick<Form, 'kind' | 'repeat'>, groupMax: number): number {
	let max = f.kind === 'blocking_off' ? maxBlockingMinutes : groupMax;
	if (f.repeat === 'weekly') max = Math.min(max, maxWeeklyMinutes);
	return max;
}

export type Problem = { field: string; message: string };

// formLength is the window's length in minutes, or NaN when the times don't parse yet.
export function formLength(f: Form): number {
	if (f.repeat === 'weekly') return nominalMinutes(f);
	const a = zonedToDate(f.startDate, f.startTime, f.zone);
	const b = zonedToDate(f.endDate, f.endTime, f.zone);
	return a && b ? Math.round((b.getTime() - a.getTime()) / 60_000) : Number.NaN;
}

// formProblem says what's wrong with the form, as the server would, naming the field; null when it can be saved.
// The Pi-hole group's existence and the overlap with other schedules are the server's to check.
export function formProblem(f: Form, groupMax: number, now: Date): Problem | null {
	const name = f.name;
	if (name.trim() === '' || [...name].length > 100) return { field: 'name', message: 'A name is 1 to 100 characters.' };
	if (name.trim() !== name) return { field: 'name', message: "A name can't start or end with a space." };
	// eslint-disable-next-line no-control-regex
	if (/[\u0000-\u001f\u007f]/.test(name)) return { field: 'name', message: "A name can't contain control characters." };
	if (f.kind !== 'blocking_off') {
		if (f.group === '') return { field: 'pihole_group', message: 'Choose a Pi-hole group.' };
		if (f.group === 'Default') return { field: 'pihole_group', message: "The Default group can't be scheduled." };
	}
	if (!isTimeZone(f.zone.trim())) return { field: 'time_zone', message: `"${f.zone}" isn't a time zone, such as Europe/London or UTC.` };
	const max = maxMinutes(f, groupMax);
	const length = formLength(f);
	if (f.repeat === 'weekly') {
		if ((f.days & allDays) === 0) return { field: 'days', message: 'Choose at least one day.' };
		if (!timePattern.test(f.start)) return { field: 'start', message: 'The start is HH:MM.' };
		if (!timePattern.test(f.end)) return { field: 'end', message: 'The end is HH:MM.' };
		if (length <= 0) return { field: 'end', message: 'The window has to end after it starts: for one past midnight, end it the next day.' };
		if (length > shortestGapMinutes(f.days)) {
			return { field: 'end_days', message: 'The window is longer than the time until it starts again, so it would overlap itself.' };
		}
		if (length > max) return { field: 'end_days', message: `The window can be at most ${lengthText(max)} long.` };
		return null;
	}
	const start = zonedToDate(f.startDate, f.startTime, f.zone.trim());
	const end = zonedToDate(f.endDate, f.endTime, f.zone.trim());
	if (!start) return { field: 'starts_at', message: 'Choose when it starts.' };
	if (!end) return { field: 'ends_at', message: 'Choose when it ends.' };
	if (start.getTime() <= now.getTime()) return { field: 'starts_at', message: 'A one-off schedule has to start in the future.' };
	if (end.getTime() <= start.getTime()) return { field: 'ends_at', message: 'The window has to end after it starts.' };
	if (length > max) return { field: 'ends_at', message: `The window can be at most ${lengthText(max)} long.` };
	return null;
}

// blankForm is a new schedule: blocking off on weekdays, in the browser's zone.
export function blankForm(zone: string): Form {
	return {
		name: '',
		kind: 'blocking_off',
		group: '',
		repeat: 'weekly',
		enabled: true,
		days: weekdays,
		start: '08:00',
		end: '08:30',
		endDays: 0,
		zone,
		startDate: '',
		startTime: '',
		endDate: '',
		endTime: ''
	};
}

// formOf fills the form from a saved schedule. A one-off window is shown in zone, the browser's.
export function formOf(s: Schedule, zone: string): Form {
	const f: Form = {
		...blankForm(s.time_zone ?? zone),
		name: s.name,
		kind: s.kind,
		group: s.pihole_group ?? '',
		repeat: s.repeat,
		enabled: s.enabled
	};
	if (s.repeat === 'weekly') {
		return { ...f, days: s.days ?? weekdays, start: s.start ?? '', end: s.end ?? '', endDays: s.end_days ?? 0 };
	}
	const a = dateToZoned(s.starts_at ?? '', zone);
	const b = dateToZoned(s.ends_at ?? '', zone);
	return { ...f, zone, startDate: a.date, startTime: a.time, endDate: b.date, endTime: b.time };
}

// inputOf is the request for a valid form.
export function inputOf(f: Form): ScheduleInput {
	const base: ScheduleInput = { name: f.name, kind: f.kind, repeat: f.repeat, enabled: f.enabled };
	if (f.kind !== 'blocking_off') base.pihole_group = f.group;
	if (f.repeat === 'weekly') {
		return { ...base, days: f.days, start: f.start, end: f.end, end_days: f.endDays, time_zone: f.zone.trim() };
	}
	return {
		...base,
		starts_at: zonedToDate(f.startDate, f.startTime, f.zone.trim())?.toISOString(),
		ends_at: zonedToDate(f.endDate, f.endTime, f.zone.trim())?.toISOString()
	};
}

// resultText says what the latest edge did on one instance.
export function resultText(r: ScheduleResult): string {
	switch (r.status) {
		case 'ok':
			switch (r.skip) {
				case 'unchanged':
					return 'Already as it should be';
				case 'still_open':
					return `Left as it is: ${r.other ?? 'another schedule'} is still open`;
				case 'window_over':
					return 'Nothing to do: the window had ended';
				case 'timer':
					return "Pi-hole's timer ends it";
			}
			return 'Done';
		case 'skipped':
			return `Couldn't reach it (${r.code ?? 'unknown'}); trying again`;
		case 'given_up':
			return `Gave up after ${r.attempts} attempts (${r.code ?? 'unknown'})`;
	}
	if (r.code === 'schedule_conflict') return `Not changed: ${r.other ?? 'another schedule'} turns it the other way`;
	return `Failed (${r.code ?? 'unknown'}); trying again`;
}

// Whether a schedule needs a look: an instance failed its latest edge, or gave up.
export function troubled(s: Schedule): boolean {
	return s.results.some((r) => r.status !== 'ok');
}

// statusLine says what one schedule is doing for the dashboard: "Blocking is off until 08:30 (schedule 'Lab
// mornings')", "bedtime turns on at 21:00 (schedule 'Bedtime')". format shows a time; a schedule set on a target
// other than current (an instance's mirrored group) names it.
export function statusLine(s: ScheduleStatusItem, format: (iso: string) => string, current?: string): string {
	const named = `(schedule '${s.name}'${current && s.target !== current ? ` on ${s.target_name}` : ''})`;
	const group = s.pihole_group ?? '';
	if (s.open && s.open_until) {
		if (s.kind === 'blocking_off') return `Blocking is off until ${format(s.open_until)} ${named}`;
		return `${group} is ${s.kind === 'group_enabled' ? 'on' : 'off'} until ${format(s.open_until)} ${named}`;
	}
	if (!s.next_edge) return `${s.name}: nothing coming up`; // the server leaves these out
	const at = format(s.next_edge.at);
	if (s.kind === 'blocking_off') return `Blocking turns off at ${at} ${named}`;
	const on = (s.kind === 'group_enabled') === (s.next_edge.edge === 'start');
	return `${group} turns ${on ? 'on' : 'off'} at ${at} ${named}`;
}

// openBlocking is the blocking window open now, for the blocking menu: the one ending last.
export function openBlocking(st: ScheduleStatus | null | undefined): ScheduleStatusItem | null {
	const open = (st?.schedules ?? []).filter((s) => s.kind === 'blocking_off' && s.open && s.open_until);
	return open.toSorted((a, b) => (b.open_until ?? '').localeCompare(a.open_until ?? ''))[0] ?? null;
}
