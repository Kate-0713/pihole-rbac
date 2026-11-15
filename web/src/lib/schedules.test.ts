// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	blankForm,
	dateToZoned,
	describeDays,
	describeWhen,
	formOf,
	formProblem,
	inputOf,
	lengthText,
	nominalMinutes,
	openBlocking,
	resultText,
	shortestGapMinutes,
	statusLine,
	suggestEndDays,
	zonedToDate,
	type Form,
	type Schedule,
	type ScheduleStatusItem
} from './schedules.js';

const now = new Date('2027-03-01T12:00:00Z'); // a Monday
const day = 24 * 60;

const schedule = (over: Partial<Schedule>): Schedule => ({
	id: 1,
	name: 'Lab mornings',
	target: 'i-1',
	target_name: 'pihole1',
	kind: 'blocking_off',
	repeat: 'weekly',
	enabled: true,
	days: 31,
	start: '08:00',
	end: '08:30',
	end_days: 0,
	time_zone: 'Europe/London',
	length_minutes: 30,
	open: false,
	results: [],
	over_limit: false,
	created_at: '2027-03-01T00:00:00Z',
	created_by: 'admin',
	updated_at: '2027-03-01T00:00:00Z',
	updated_by: 'admin',
	...over
});

describe('describing a schedule', () => {
	it('names the days', () => {
		expect(describeDays(127)).toBe('Every day');
		expect(describeDays(31)).toBe('Weekdays');
		expect(describeDays(96)).toBe('Weekends');
		expect(describeDays(1 | 4 | 16)).toBe('Mon, Wed, Fri');
	});
	it('says when its windows happen', () => {
		const iso = (s: string) => s;
		expect(describeWhen(schedule({}), iso)).toBe('Weekdays 08:00–08:30');
		expect(describeWhen(schedule({ days: 127, start: '21:00', end: '07:00', end_days: 1 }), iso)).toBe(
			'Every day 21:00 to 07:00 the next day'
		);
		expect(describeWhen(schedule({ days: 16, start: '18:00', end: '07:00', end_days: 3 }), iso)).toBe('Fri 18:00 to 07:00, 3 days later');
		expect(describeWhen(schedule({ repeat: 'once', starts_at: 'A', ends_at: 'B' }), iso)).toBe('A to B');
	});
	it('names lengths', () => {
		expect(lengthText(30)).toBe('30 minutes');
		expect(lengthText(day)).toBe('24 hours');
		expect(lengthText(600)).toBe('10 hours');
		expect(lengthText(day + 12 * 60)).toBe('1 day 12 hours');
		expect(lengthText(7 * day)).toBe('7 days');
		expect(lengthText(90)).toBe('1 hour 30 minutes');
	});
});

describe('the window maths, as the server does it', () => {
	it('works out a weekly length, with no wrap past midnight', () => {
		expect(nominalMinutes({ start: '08:00', end: '08:30', endDays: 0 })).toBe(30);
		expect(nominalMinutes({ start: '21:00', end: '07:00', endDays: 1 })).toBe(600);
		expect(nominalMinutes({ start: '21:00', end: '07:00', endDays: 0 })).toBe(-840);
		expect(Number.isNaN(nominalMinutes({ start: '8:00', end: '08:30', endDays: 0 }))).toBe(true);
	});
	it('finds the shortest gap between selected days', () => {
		expect(shortestGapMinutes(1)).toBe(7 * day);
		expect(shortestGapMinutes(127)).toBe(day);
		expect(shortestGapMinutes(1 | 16)).toBe(3 * day); // Friday to Monday
		expect(shortestGapMinutes(0)).toBe(0);
	});
	it('suggests the next day for a window that ends at or before its start', () => {
		expect(suggestEndDays('21:00', '07:00')).toBe(1);
		expect(suggestEndDays('08:00', '08:00')).toBe(1);
		expect(suggestEndDays('08:00', '08:30')).toBe(0);
	});
	it('turns a wall-clock time in a zone into an instant, across daylight saving', () => {
		expect(zonedToDate('2027-03-01', '08:00', 'Europe/London')?.toISOString()).toBe('2027-03-01T08:00:00.000Z');
		expect(zonedToDate('2027-07-01', '08:00', 'Europe/London')?.toISOString()).toBe('2027-07-01T07:00:00.000Z');
		// 01:30 doesn't happen in London on 28 March 2027: it comes out an hour later, 02:30 BST, as on the server.
		expect(zonedToDate('2027-03-28', '01:30', 'Europe/London')?.toISOString()).toBe('2027-03-28T01:30:00.000Z');
		expect(zonedToDate('2027-03-01', '08:00', 'Nowhere/City')).toBeNull();
		expect(zonedToDate('2027-3-1', '08:00', 'UTC')).toBeNull();
	});
	it('reads an instant back as a wall-clock time', () => {
		expect(dateToZoned('2027-07-01T07:00:00Z', 'Europe/London')).toEqual({ date: '2027-07-01', time: '08:00' });
		expect(dateToZoned('2027-03-01T23:30:00Z', 'Asia/Tokyo')).toEqual({ date: '2027-03-02', time: '08:30' });
	});
});

describe('formProblem', () => {
	const weekly = (over: Partial<Form>): Form => ({ ...blankForm('UTC'), name: 'Lab', ...over });
	const once = (start: string, end: string, over: Partial<Form> = {}): Form => {
		const [sd, st] = start.split(' ');
		const [ed, et] = end.split(' ');
		return weekly({ repeat: 'once', startDate: sd, startTime: st, endDate: ed, endTime: et, ...over });
	};
	const group = (over: Partial<Form>) => weekly({ kind: 'group_enabled', group: 'bedtime', ...over });
	const cases: [string, Form, number, string | null][] = [
		['a weekday blocking window', weekly({}), day, null],
		['a group window past midnight', group({ days: 127, start: '21:00', end: '07:00', endDays: 1 }), day, null],
		['a whole week with a long limit', group({ days: 1, start: '00:00', end: '00:00', endDays: 7 }), 365 * day, null],
		['a one-off', once('2027-03-02 08:00', '2027-03-02 09:00'), day, null],
		['a 24-hour blocking window', weekly({ days: 1, start: '08:00', end: '08:00', endDays: 1 }), day, null],
		['no name', weekly({ name: '' }), day, 'name'],
		['a trailing space', weekly({ name: 'Lab ' }), day, 'name'],
		['a control character', weekly({ name: 'a\nb' }), day, 'name'],
		['a group window without a group', group({ group: '' }), day, 'pihole_group'],
		['the Default group', group({ group: 'Default' }), day, 'pihole_group'],
		['an unknown zone', weekly({ zone: 'Mars/Olympus' }), day, 'time_zone'],
		['no days', weekly({ days: 0 }), day, 'days'],
		['ending as it starts', weekly({ start: '08:00', end: '08:00' }), day, 'end'],
		['past midnight without the next day', group({ start: '21:00', end: '07:00', endDays: 0 }), day, 'end'],
		['overlapping itself', group({ days: 1 | 2, start: '08:00', end: '20:00', endDays: 1 }), 7 * day, 'end_days'],
		['a blocking window over 24 hours', weekly({ days: 1, start: '08:00', end: '09:00', endDays: 1 }), day, 'end_days'],
		['a group window over the limit', group({ days: 1, start: '08:00', end: '10:00' }), 60, 'end_days'],
		['a one-off group window over the limit', once('2027-03-02 08:00', '2027-03-03 09:00', { kind: 'group_enabled', group: 'x' }), day, 'ends_at'],
		['a one-off in the past', once('2027-03-01 11:00', '2027-03-01 13:00'), day, 'starts_at'],
		['a one-off ending as it starts', once('2027-03-02 08:00', '2027-03-02 08:00'), day, 'ends_at'],
		['a one-off without a start', once(' ', '2027-03-02 08:00'), day, 'starts_at']
	];
	for (const [name, form, max, field] of cases) {
		it(name, () => {
			expect(formProblem(form, max, now)?.field ?? null).toBe(field);
		});
	}
	it('says what the limit is', () => {
		expect(formProblem(group({ days: 1, start: '08:00', end: '10:00' }), 90, now)?.message).toBe(
			'The window can be at most 1 hour 30 minutes long.'
		);
	});
});

describe('the request and back', () => {
	it('builds a weekly request', () => {
		const f: Form = { ...blankForm('Europe/London'), name: 'Bedtime', kind: 'group_enabled', group: 'bedtime', days: 127, start: '21:00', end: '07:00', endDays: 1 };
		expect(inputOf(f)).toEqual({
			name: 'Bedtime',
			kind: 'group_enabled',
			pihole_group: 'bedtime',
			repeat: 'weekly',
			enabled: true,
			days: 127,
			start: '21:00',
			end: '07:00',
			end_days: 1,
			time_zone: 'Europe/London'
		});
	});
	it('builds a one-off request in the chosen zone', () => {
		const f: Form = { ...blankForm('Europe/London'), name: 'x', repeat: 'once', startDate: '2027-07-01', startTime: '08:00', endDate: '2027-07-01', endTime: '09:00' };
		const body = inputOf(f);
		expect(body.starts_at).toBe('2027-07-01T07:00:00.000Z');
		expect(body.ends_at).toBe('2027-07-01T08:00:00.000Z');
		expect(body.pihole_group).toBeUndefined();
		expect(body.days).toBeUndefined();
	});
	it('fills the form from a saved schedule', () => {
		expect(formOf(schedule({ kind: 'group_disabled', pihole_group: 'strict' }), 'UTC')).toMatchObject({
			name: 'Lab mornings',
			kind: 'group_disabled',
			group: 'strict',
			days: 31,
			start: '08:00',
			end: '08:30',
			zone: 'Europe/London'
		});
		const o = formOf(schedule({ repeat: 'once', starts_at: '2027-07-01T07:00:00Z', ends_at: '2027-07-01T08:00:00Z' }), 'Europe/London');
		expect(o).toMatchObject({ repeat: 'once', zone: 'Europe/London', startDate: '2027-07-01', startTime: '08:00', endTime: '09:00' });
	});
});

describe('results and status', () => {
	const r = (over: Partial<Schedule['results'][number]>) => ({ instance_id: 1, instance: 'pihole1', status: 'ok' as const, at: '', attempts: 1, ...over });
	it('says what an edge did', () => {
		expect(resultText(r({}))).toBe('Done');
		expect(resultText(r({ skip: 'still_open', other: 'Early' }))).toBe('Left as it is: Early is still open');
		expect(resultText(r({ status: 'failed', code: 'not_found' }))).toBe('Failed (not_found); trying again');
		expect(resultText(r({ status: 'failed', code: 'schedule_conflict', other: 'Off' }))).toBe('Not changed: Off turns it the other way');
		expect(resultText(r({ status: 'given_up', code: 'internal', attempts: 9 }))).toBe('Gave up after 9 attempts (internal)');
	});
	const item = (over: Partial<ScheduleStatusItem>): ScheduleStatusItem => ({
		id: 1,
		name: 'Lab mornings',
		kind: 'blocking_off',
		target: 'i-1',
		target_name: 'pihole1',
		open: false,
		...over
	});
	const at = (iso: string) => iso.slice(11, 16);
	it('describes a schedule for the dashboard', () => {
		expect(statusLine(item({ next_edge: { at: '2027-03-02T08:00:00Z', edge: 'start' } }), at, 'i-1')).toBe(
			"Blocking turns off at 08:00 (schedule 'Lab mornings')"
		);
		expect(statusLine(item({ open: true, open_until: '2027-03-02T08:30:00Z' }), at, 'i-1')).toBe(
			"Blocking is off until 08:30 (schedule 'Lab mornings')"
		);
		const bedtime = item({ name: 'Bedtime', kind: 'group_enabled', pihole_group: 'bedtime', target: 'g-1', target_name: 'site' });
		expect(statusLine({ ...bedtime, next_edge: { at: '2027-03-01T21:00:00Z', edge: 'start' } }, at, 'i-1')).toBe(
			"bedtime turns on at 21:00 (schedule 'Bedtime' on site)"
		);
		expect(statusLine({ ...bedtime, kind: 'group_disabled', next_edge: { at: '2027-03-01T21:00:00Z', edge: 'end' } }, at, 'g-1')).toBe(
			"bedtime turns on at 21:00 (schedule 'Bedtime')"
		);
	});
	it('finds the open blocking window that ends last', () => {
		expect(openBlocking(null)).toBeNull();
		const st = {
			schedules: [
				item({ id: 1, open: true, open_until: '2027-03-02T08:30:00Z' }),
				item({ id: 2, open: true, open_until: '2027-03-02T10:00:00Z' }),
				item({ id: 3, kind: 'group_enabled', open: true, open_until: '2027-03-03T10:00:00Z' })
			]
		};
		expect(openBlocking(st)?.id).toBe(2);
	});
});
