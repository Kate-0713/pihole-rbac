// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	badgeOf,
	blankForm,
	canEnd,
	canExtend,
	currentFor,
	dashboardItems,
	endProblem,
	extendProblem,
	formProblem,
	latestEnd,
	memberText,
	presetsWithin,
	remainingText,
	retryable,
	startBody,
	summaryLine,
	type Form,
	type Limits,
	type TempChange,
	type TempMember
} from './temp-changes.js';

const now = new Date('2026-11-15T12:00:00Z');
const at = (min: number) => new Date(now.getTime() + min * 60_000).toISOString();
const fmt = (iso: string) => `T${iso.slice(11, 16)}`;

function member(over: Partial<TempMember> = {}): TempMember {
	return {
		instance_id: 1,
		instance: 'pihole1',
		original_groups: ['Default'],
		override_groups: ['Open'],
		revert_status: 'pending',
		attempts: 0,
		...over
	};
}
function change(over: Partial<TempChange> = {}): TempChange {
	return {
		id: 1,
		target: 'i-1',
		target_name: 'pihole1',
		client: '10.0.0.5',
		starts_at: at(-10),
		ends_at: at(50),
		reason: 'homework',
		status: 'active',
		overdue: false,
		created_by: 'kate',
		members: [member()],
		...over
	};
}
const limits: Limits = { max_minutes: 24 * 60, reason_required: true };
const groups = [
	{ id: 0, name: 'Default', enabled: true },
	{ id: 3, name: 'Open', enabled: true }
] as never[];

describe('presetsWithin', () => {
	it.each([
		[5, []],
		[15, [15]],
		[90, [15, 60]],
		[10080, [15, 60, 240]]
	])('max %i minutes offers %j', (max, want) => {
		expect(presetsWithin(max).map((p) => p.minutes)).toEqual(want);
	});
});

describe('badgeOf', () => {
	it.each([
		['active', change(), { kind: 'active', label: 'Temporary until T12:50' }],
		['overdue', change({ overdue: true }), { kind: 'overdue', label: 'Overdue, reverting' }],
		[
			'through a group',
			change({ via: 'g-2', target: 'g-2', target_name: 'Kids' }),
			{ kind: 'through', label: 'Temporary until T12:50, set through Kids' }
		],
		[
			'failed with a member given up',
			change({ status: 'failed', members: [member({ revert_status: 'given_up' })] }),
			{ kind: 'failed', label: 'Revert failed' }
		],
		['failed, only a deleted client', change({ status: 'failed', members: [member({ revert_status: 'failed', revert_code: 'not_found' })] }), null],
		['reverted', change({ status: 'reverted' }), null],
		['ended', change({ status: 'ended' }), null]
	])('%s', (_name, c, want) => {
		expect(badgeOf(c, fmt)).toEqual(want);
	});
});

describe('actions', () => {
	it('lets an own active change be extended and ended', () => {
		expect(canExtend(change())).toBe(true);
		expect(canEnd(change())).toBe(true);
	});
	it('does not extend an overdue one, but ends it', () => {
		expect(canExtend(change({ overdue: true }))).toBe(false);
		expect(canEnd(change({ overdue: true }))).toBe(true);
	});
	it('leaves a change set through a group read-only', () => {
		const c = change({ via: 'g-2' });
		expect([canExtend(c), canEnd(c)]).toEqual([false, false]);
	});
	it('offers a retry only for a failed change with a member given up', () => {
		expect(retryable(change({ status: 'failed', members: [member({ revert_status: 'given_up' })] }))).toBe(true);
		expect(retryable(change({ status: 'failed', members: [member({ revert_status: 'failed' })] }))).toBe(false);
		expect(retryable(change())).toBe(false);
	});
});

describe('currentFor', () => {
	it('prefers the active change, then one to retry, for the client', () => {
		const old = change({ id: 1, status: 'reverted' });
		const active = change({ id: 2 });
		const failed = change({ id: 3, status: 'failed', members: [member({ revert_status: 'given_up' })] });
		expect(currentFor([old, failed, active], '10.0.0.5')?.id).toBe(2);
		expect(currentFor([old, failed], '10.0.0.5')?.id).toBe(3);
		expect(currentFor([old], '10.0.0.5')).toBeNull();
		expect(currentFor([active], '10.0.0.9')).toBeNull();
	});
});

describe('remainingText', () => {
	it.each([
		[at(0.5), 'less than a minute left'],
		[at(1), '1 minute left'],
		[at(65), '1 hour 5 minutes left'],
		[at(0), 'time is up'],
		[at(-5), 'time is up']
	])('%s', (end, want) => {
		expect(remainingText(end, now)).toBe(want);
	});
});

describe('endProblem and the limit from the start', () => {
	const from = new Date(at(-10));
	it('measures the limit from the start, not from now', () => {
		// 24 hours from the start is 23 h 50 min from now.
		expect(endProblem(new Date(at(24 * 60 - 10)), from, now, 24 * 60)).toBeNull();
		expect(endProblem(new Date(at(24 * 60 - 9)), from, now, 24 * 60)).toMatch(/at most 24 hours/);
	});
	it('refuses the past and a missing time', () => {
		expect(endProblem(new Date(at(-1)), from, now, 24 * 60)).toMatch(/future/);
		expect(endProblem(null, from, now, 24 * 60)).toMatch(/date and time/);
	});
	it('gives the latest end as the start plus the limit', () => {
		expect(latestEnd({ starts_at: at(-10) }, 60).toISOString()).toBe(at(50));
	});
});

describe('formProblem', () => {
	const current = [0];
	const form = (over: Partial<Form> = {}): Form => ({ ...blankForm(current, limits.max_minutes), groups: [0, 3], reason: 'homework', ...over });
	const zone = 'UTC';

	it('accepts a good start', () => {
		expect(formProblem(form(), current, limits, now, zone)).toBeNull();
	});
	it('refuses the groups the client already has', () => {
		expect(formProblem(form({ groups: [0] }), current, limits, now, zone)?.field).toBe('groups');
		expect(formProblem(form({ groups: [3, 0] }), [0, 3], limits, now, zone)?.field).toBe('groups');
	});
	it('allows an empty set of groups only if it differs', () => {
		expect(formProblem(form({ groups: [] }), current, limits, now, zone)).toBeNull();
	});
	it.each([
		[4, 'duration'],
		[5, null],
		[24 * 60, null],
		[24 * 60 + 1, 'duration']
	])('a preset of %i minutes', (minutes, field) => {
		expect(formProblem(form({ minutes }), current, limits, now, zone)?.field ?? null).toBe(field);
	});
	it('checks a chosen end', () => {
		const until = (date: string, time: string) => form({ mode: 'until', untilDate: date, untilTime: time });
		expect(formProblem(until('2026-11-15', '14:00'), current, limits, now, zone)).toBeNull();
		expect(formProblem(until('2026-11-15', '11:00'), current, limits, now, zone)?.message).toMatch(/future/);
		expect(formProblem(until('2026-11-15', '12:03'), current, limits, now, zone)?.message).toMatch(/at least 5 minutes/);
		expect(formProblem(until('2026-11-17', '12:00'), current, limits, now, zone)?.message).toMatch(/at most 24 hours/);
		expect(formProblem(until('', ''), current, limits, now, zone)?.field).toBe('duration');
	});
	it('needs a reason only when the setting says so', () => {
		expect(formProblem(form({ reason: '  ' }), current, limits, now, zone)?.field).toBe('reason');
		expect(formProblem(form({ reason: '' }), current, { ...limits, reason_required: false }, now, zone)).toBeNull();
		expect(formProblem(form({ reason: 'x'.repeat(201) }), current, { ...limits, reason_required: false }, now, zone)?.field).toBe('reason');
		expect(formProblem(form({ reason: 'x'.repeat(200) }), current, limits, now, zone)).toBeNull();
	});
});

describe('startBody', () => {
	const f = (over: Partial<Form> = {}): Form => ({ ...blankForm([0], 10080), groups: [3], reason: ' homework ', ...over });
	it('names the groups and sends the length of a preset', () => {
		expect(startBody('10.0.0.5', f({ minutes: 60 }), groups, now, 'UTC')).toEqual({
			client: '10.0.0.5',
			groups: ['Open'],
			duration_minutes: 60,
			reason: 'homework'
		});
	});
	it('sends the end of a chosen time, in UTC', () => {
		const body = startBody('10.0.0.5', f({ mode: 'until', untilDate: '2026-11-15', untilTime: '15:30', reason: '' }), groups, now, 'Europe/London');
		expect(body).toEqual({ client: '10.0.0.5', groups: ['Open'], ends_at: '2026-11-15T15:30:00.000Z' });
	});
});

describe('extendProblem', () => {
	const c = change();
	const end = (min: number) => new Date(at(min));
	it('accepts a later end within the limit and a shorter one in the future', () => {
		expect(extendProblem(c, end(110), limits, now)).toBeNull();
		expect(extendProblem(c, end(20), limits, now)).toBeNull();
	});
	it('refuses the same end, the past and one beyond the limit from the start', () => {
		expect(extendProblem(c, end(50), limits, now)).toMatch(/already/);
		expect(extendProblem(c, end(-1), limits, now)).toMatch(/future/);
		expect(extendProblem(c, end(24 * 60), limits, now)).toMatch(/at most/);
		expect(extendProblem(c, null, limits, now)).toMatch(/date and time/);
	});
});

describe('memberText', () => {
	it.each([
		[member(), 'pihole1: not put back yet'],
		[member({ revert_status: 'ok' }), 'pihole1: put back'],
		[member({ revert_status: 'ok', missing_groups: ['Kids'] }), 'pihole1: put back (Kids no longer exists)'],
		[member({ revert_status: 'skipped', revert_code: 'instance_down' }), "pihole1: couldn't be put back (instance_down), trying again"],
		[member({ revert_status: 'given_up' }), 'pihole1: gave up after a week']
	])('%#', (m, want) => {
		expect(memberText(m)).toBe(want);
	});
});

describe('the dashboard card', () => {
	const failed = change({ id: 1, ends_at: at(-60), status: 'failed', members: [member({ revert_status: 'given_up' })] });
	const overdue = change({ id: 2, ends_at: at(-1), overdue: true });
	const soon = change({ id: 3, ends_at: at(10), client: '10.0.0.6' });
	const later = change({ id: 4, ends_at: at(90), client: '10.0.0.7' });
	const done = change({ id: 5, status: 'reverted' });
	const lostClient = change({ id: 6, status: 'failed', members: [member({ revert_status: 'failed', revert_code: 'not_found' })] });

	it('lists what needs a look first, then by end, and leaves out the finished', () => {
		expect(dashboardItems([later, done, soon, lostClient, overdue, failed]).map((c) => c.id)).toEqual([1, 2, 3, 4]);
	});
	it('does not change the list it is given', () => {
		const input = [later, soon];
		dashboardItems(input);
		expect(input.map((c) => c.id)).toEqual([4, 3]);
	});
	it.each([
		[soon, '10.0.0.6 · 10 minutes left'],
		[overdue, '10.0.0.5 · time is up, putting it back'],
		[failed, '10.0.0.5 · revert failed']
	])('says %#', (c, want) => {
		expect(summaryLine(c, now)).toBe(want);
	});
});
