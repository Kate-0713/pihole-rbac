// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Temporary client group changes (v2.6.0): the types, and the rules the dialogs and the clients table share. All of it
// is plain functions, so the Vitest file can test it without a browser. The server checks every one of these rules
// again; the copies here are so a form can say what is wrong as you type.
import type { Schemas } from '#lib/api/client.js';
import { groupNames, type PiholeGroup } from '#lib/pihole.js';
import { dateToZoned, lengthText, zonedToDate } from '#lib/schedules.js';

export type TempChange = Schemas['TemporaryClientChange'];
export type TempChangeList = Schemas['TemporaryClientChangeList'];
export type TempChangeStart = Schemas['TemporaryClientStart'];
export type TempMember = Schemas['TemporaryClientMember'];

export const minMinutes = 5;
export const maxReasonChars = 200;

// The quick durations the start dialog offers, those within the limit only. "Until a chosen time" is the other choice.
export const presets = [
	{ minutes: 15, label: '15 minutes' },
	{ minutes: 60, label: '1 hour' },
	{ minutes: 240, label: '4 hours' }
] as const;

export function presetsWithin(maxMinutes: number): { minutes: number; label: string }[] {
	return presets.filter((p) => p.minutes <= maxMinutes);
}

// The quick additions the extend dialog offers, added to the current end.
export const additions = presets;

// A badge is what a client's row says about its change. 'failed' is shown only while something can still be done: a
// member was given up on, which Retry tries again.
export type Badge = { kind: 'active' | 'overdue' | 'failed' | 'through'; label: string };

export function retryable(c: TempChange): boolean {
	return c.status === 'failed' && !c.via && c.members.some((m) => m.revert_status === 'given_up');
}

// The change a client's row shows: its active one, else a failed one waiting for a retry. A change listed through a
// mirrored group (`via`) is the group's, shown read-only on the member.
export function currentFor(changes: readonly TempChange[], client: string): TempChange | null {
	const mine = changes.filter((c) => c.client === client);
	return mine.find((c) => c.status === 'active') ?? mine.find(retryable) ?? null;
}

export function badgeOf(c: TempChange, format: (iso: string) => string): Badge | null {
	if (c.status === 'failed') return retryable(c) ? { kind: 'failed', label: 'Revert failed' } : null;
	if (c.status !== 'active') return null;
	if (c.overdue) return { kind: 'overdue', label: 'Overdue, reverting' };
	if (c.via) return { kind: 'through', label: `Temporary until ${format(c.ends_at)}, set through ${c.target_name}` };
	return { kind: 'active', label: `Temporary until ${format(c.ends_at)}` };
}

// The dashboard card's rows: the changes that need a look first (overdue, or a revert that failed), then by when they
// end. Finished changes aren't listed.
export function dashboardItems(changes: readonly TempChange[]): TempChange[] {
	const rank = (c: TempChange) => (retryable(c) ? 0 : c.overdue ? 1 : 2);
	return changes
		.filter((c) => c.status === 'active' || retryable(c))
		.sort((a, b) => rank(a) - rank(b) || a.ends_at.localeCompare(b.ends_at));
}

// One row's text: "10.0.0.5 · 1 hour 5 minutes left".
export function summaryLine(c: TempChange, now: Date): string {
	const state = retryable(c) ? 'revert failed' : c.overdue ? 'time is up, putting it back' : remainingText(c.ends_at, now);
	return `${c.client} · ${state}`;
}

// What can be done to a change from this target: only its own, and an active one can be extended or ended.
export function canExtend(c: TempChange): boolean {
	return c.status === 'active' && !c.via && !c.overdue;
}
export function canEnd(c: TempChange): boolean {
	return c.status === 'active' && !c.via;
}

// remainingText says how long is left: "1 hour 5 minutes left", or "less than a minute left". Past the end it says so.
export function remainingText(endsAt: string, now: Date): string {
	const ms = new Date(endsAt).getTime() - now.getTime();
	if (Number.isNaN(ms)) return '';
	if (ms <= 0) return 'time is up';
	const minutes = Math.ceil(ms / 60_000);
	if (ms < 60_000) return 'less than a minute left';
	return `${lengthText(minutes)} left`;
}

// The newest end an extension may have: the limit is measured from the start, so extending can't get round it.
export function latestEnd(c: Pick<TempChange, 'starts_at'>, maxMinutes: number): Date {
	return new Date(new Date(c.starts_at).getTime() + maxMinutes * 60_000);
}

// The form of the start dialog.
export type Form = {
	groups: number[];
	// 'preset' uses minutes; 'until' uses the date and time, in the browser's zone.
	mode: 'preset' | 'until';
	minutes: number;
	untilDate: string;
	untilTime: string;
	reason: string;
};

export type Limits = { max_minutes: number; reason_required: boolean };
export type Problem = { field: 'groups' | 'duration' | 'reason'; message: string };

export function blankForm(current: readonly number[], maxMinutes: number): Form {
	const first = presetsWithin(maxMinutes)[1] ?? presetsWithin(maxMinutes)[0];
	return {
		groups: [...current],
		mode: first ? 'preset' : 'until',
		minutes: first?.minutes ?? minMinutes,
		untilDate: '',
		untilTime: '',
		reason: ''
	};
}

const same = (a: readonly number[], b: readonly number[]) => a.length === b.length && [...a].sort().join() === [...b].sort().join();

// The end the form asks for, or null when the date and time aren't a real one.
export function endOf(f: Form, now: Date, zone: string): Date | null {
	if (f.mode === 'preset') return new Date(now.getTime() + f.minutes * 60_000);
	return zonedToDate(f.untilDate, f.untilTime, zone);
}

// endProblem is what is wrong with an end time against the limit, measured from `from` (the start: now for a new
// change, the change's own start for an extension). The server's limit is on ends_at minus starts_at.
export function endProblem(end: Date | null, from: Date, now: Date, maxMinutes: number): string | null {
	if (!end) return 'Choose a date and time.';
	if (end.getTime() <= now.getTime()) return 'Choose a time in the future.';
	if (end.getTime() - from.getTime() > maxMinutes * 60_000) {
		return `A change can last at most ${lengthText(maxMinutes)} from its start.`;
	}
	return null;
}

// formProblem is the first thing wrong with a start, or null. `current` is the client's groups now, so asking for the
// same ones (which would change nothing) is said here and not only by the server.
export function formProblem(f: Form, current: readonly number[], limits: Limits, now: Date, zone: string): Problem | null {
	if (same(f.groups, current)) return { field: 'groups', message: "These are the client's groups already. Change them for the time." };
	if (f.mode === 'preset') {
		if (f.minutes < minMinutes || f.minutes > limits.max_minutes) {
			return { field: 'duration', message: `Choose between ${lengthText(minMinutes)} and ${lengthText(limits.max_minutes)}.` };
		}
	} else {
		const end = endOf(f, now, zone);
		const p = endProblem(end, now, now, limits.max_minutes);
		if (p) return { field: 'duration', message: p };
		if (end && end.getTime() - now.getTime() < minMinutes * 60_000) {
			return { field: 'duration', message: `A change lasts at least ${lengthText(minMinutes)}.` };
		}
	}
	const reason = f.reason.trim();
	if (limits.reason_required && reason === '') return { field: 'reason', message: 'Say why. It is kept with the change and shown in the audit log.' };
	if ([...reason].length > maxReasonChars) return { field: 'reason', message: `The reason can be at most ${maxReasonChars} characters.` };
	return null;
}

// startBody is the request: the groups by name, and either the length or the end.
export function startBody(client: string, f: Form, groups: readonly PiholeGroup[], now: Date, zone: string): TempChangeStart {
	const body: TempChangeStart = { client, groups: groupNames(f.groups, groups) };
	if (f.mode === 'preset') body.duration_minutes = f.minutes;
	else body.ends_at = (endOf(f, now, zone) ?? now).toISOString();
	const reason = f.reason.trim();
	if (reason !== '') body.reason = reason;
	return body;
}

// The extend dialog edits the end alone, as a date and time in the browser's zone.
export function endForm(c: Pick<TempChange, 'ends_at'>, zone: string): { date: string; time: string } {
	return dateToZoned(c.ends_at, zone);
}

export function extendProblem(c: TempChange, end: Date | null, limits: Limits, now: Date): string | null {
	if (!end) return 'Choose a date and time.';
	if (end.getTime() === new Date(c.ends_at).getTime()) return 'That is the end it has already.';
	return endProblem(end, new Date(c.starts_at), now, limits.max_minutes);
}

// What a member's row says, for the details of a change.
export function memberText(m: TempMember): string {
	switch (m.revert_status) {
		case 'pending':
			return `${m.instance}: not put back yet`;
		case 'ok':
			return m.missing_groups?.length
				? `${m.instance}: put back (${m.missing_groups.join(', ')} no longer exists)`
				: `${m.instance}: put back`;
		case 'failed':
		case 'skipped':
			return `${m.instance}: couldn't be put back${m.revert_code ? ` (${m.revert_code})` : ''}, trying again`;
		case 'given_up':
			return `${m.instance}: gave up after a week${m.revert_code ? ` (${m.revert_code})` : ''}`;
	}
}
