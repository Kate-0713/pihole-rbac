// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	byScope,
	describeCode,
	describePreview,
	describeRule,
	describeRun,
	emptyRow,
	isTimeZone,
	nextRun,
	parseGroupList,
	rulesProblem,
	runCounts,
	scheduleProblem,
	timeZones,
	toRuleRows,
	toRulesInput,
	type InstanceResult,
	type Rule,
	type RuleRow
} from './clientreset.js';

const rule = (over: Partial<Rule> = {}): Rule => ({
	scope: 'instance',
	id: 1,
	name: 'pihole1',
	comment_prefix: 'TEST-',
	group_match: 'names',
	pihole_groups: ['AUTOSET-lab'],
	...over
});

const row = (over: Partial<RuleRow> = {}): RuleRow => ({ scope: 'instance:1', prefix: 'TEST-', match: 'names', groups: 'AUTOSET-lab', ...over });

const result = (over: Partial<InstanceResult> = {}): InstanceResult => ({
	instance_id: 1,
	instance: 'pihole1',
	primary: false,
	status: 'ok',
	reset: [],
	failed: [],
	unchanged: 0,
	problems: [],
	...over
});

const change = { client: '10.0.0.1', comment: 'TEST-x', prefix: 'TEST-', groups_before: ['Default'], groups_after: ['AUTOSET-lab'] };

describe('parseGroupList', () => {
	it('trims, drops empty ones and exact repeats, and keeps case', () => {
		expect(parseGroupList(' AUTOSET-lab, ,kids,Kids , kids')).toEqual(['AUTOSET-lab', 'kids', 'Kids']);
		expect(parseGroupList('')).toEqual([]);
	});
});

describe('rule rows', () => {
	it('round-trips through the form', () => {
		const rules = [rule(), rule({ scope: 'group', id: 2, name: 'site', group_match: 'prefixes', pihole_groups: ['A', 'B'] })];
		const rows = toRuleRows(rules);
		expect(rows[1]).toEqual({ scope: 'group:2', prefix: 'TEST-', match: 'prefixes', groups: 'A, B' });
		expect(toRulesInput(rows).rules).toEqual(
			rules.map((r) => ({ scope: r.scope, id: r.id, comment_prefix: r.comment_prefix, group_match: r.group_match, pihole_groups: r.pihole_groups }))
		);
	});

	it.each([
		[[row({ scope: '' })], 'Rule 1: choose an instance or mirrored group.'],
		[[row({ prefix: '' })], /comment prefix is 1-255/],
		[[row({ prefix: '   ' })], /not only spaces/],
		[[row({ prefix: 'a\tb' })], /control characters/],
		[[row({ prefix: 'x'.repeat(256) })], /1-255/],
		[[row(), row({ groups: 'other' })], 'Rule 2: "TEST-" is already used on that instance or group.'],
		[[row({ groups: ' , ' })], 'Rule 1: name at least one Pi-hole group.'],
		[[row({ groups: Array.from({ length: 51 }, (_, i) => `g${i}`).join(',') })], /at most 50/],
		[[row({ groups: 'x'.repeat(256) })], /a Pi-hole group is/]
	])('refuses %j', (rows, want) => {
		const got = rulesProblem(rows);
		if (want instanceof RegExp) expect(got).toMatch(want);
		else expect(got).toBe(want);
	});

	it('accepts the same prefix on another scope, and a new empty row is incomplete', () => {
		expect(rulesProblem([row(), row({ scope: 'group:2' })])).toBeNull();
		expect(rulesProblem([emptyRow()])).toMatch(/choose an instance/);
		expect(rulesProblem([])).toBeNull();
	});
});

describe('describing rules', () => {
	it('says what a rule does', () => {
		expect(describeRule(rule({ pihole_groups: ['AUTOSET-lab', 'kids'] }))).toBe('"TEST-" → AUTOSET-lab, kids');
		expect(describeRule(rule({ group_match: 'prefixes', pihole_groups: ['AUTOSET-'] }))).toBe('"TEST-" → AUTOSET-…');
	});

	it('groups rules by what they are set on, in order', () => {
		const got = byScope([rule(), rule({ comment_prefix: 'NINJA-' }), rule({ scope: 'group', id: 1, name: 'site' })]);
		expect(got.map((g) => [g.key, g.name, g.rules.length])).toEqual([
			['instance:1', 'pihole1', 2],
			['group:1', 'site', 1]
		]);
	});
});

describe('describing runs', () => {
	it('adds up the instances', () => {
		const instances = [
			result({ reset: [change, change], unchanged: 3 }),
			result({ failed: [{ client: 'x', comment: '', prefix: 'TEST-', code: 'pihole_rejected' }] }),
			result({ status: 'skipped', code: 'pihole_unreachable' })
		];
		expect(runCounts(instances)).toEqual({ reset: 2, failed: 1, unchanged: 3, unread: 1, broken: 0 });
		expect(describeRun({ status: 'partial', instances })).toBe('2 clients reset, 1 failed, 1 instance not reached');
	});

	it('says when there was nothing to do, a run is running, or it was interrupted', () => {
		expect(describeRun({ status: 'ok', instances: [result({ unchanged: 4 })] })).toBe('Nothing to change');
		expect(describeRun({ status: 'ok', instances: [result({ reset: [change] })] })).toBe('1 client reset');
		// A rule that can't run is said even when no client matched it yet, counted once across instances.
		const problems = [{ prefix: 'NINJA-', code: 'pihole_group_missing' as const, missing: ['AUTOSET-lab'] }];
		expect(describeRun({ status: 'ok', instances: [result({ problems }), result({ problems })] })).toBe("1 rule can't run");
		expect(describeRun({ status: 'running', instances: [] })).toBe('Running…');
		expect(describeRun({ status: 'failed', instances: [], error: 'interrupted: the app stopped during the run' })).toMatch(/^interrupted/);
	});

	it('describes a preview', () => {
		const p = { target: 'g-1', target_name: 'site', rules: 1, instances: [result({ reset: [change] }), result({ instance: 'pihole2', unchanged: 1 })] };
		expect(describePreview(p)).toBe('Would reset 1 client on pihole1.');
		expect(describePreview({ ...p, instances: [result({ unchanged: 2 })] })).toMatch(/^Nothing to reset/);
	});

	it('words codes, and passes on ones it does not know', () => {
		expect(describeCode('pihole_group_missing')).toMatch(/aren't all on this Pi-hole/);
		expect(describeCode('something_new')).toBe('something_new');
	});
});

describe('the schedule', () => {
	it('checks the time and zone as the server does', () => {
		expect(scheduleProblem({ enabled: true, time: '03:00', time_zone: 'Europe/London' })).toBeNull();
		for (const time of ['3:00', '24:00', '03:60', '0300', '']) {
			expect(scheduleProblem({ enabled: true, time, time_zone: 'UTC' }), time).toMatch(/HH:MM/);
		}
		for (const zone of ['', 'Local', 'Mars/Olympus_Mons', 'x'.repeat(65)]) {
			expect(isTimeZone(zone), zone).toBe(false);
		}
		expect(timeZones()[0]).toBe('UTC');
		expect(timeZones()).toContain('Europe/London');
	});

	const utc = (s: string) => new Date(`${s}Z`);
	it.each([
		['later today', '03:00', 'UTC', '2026-10-25T01:00:00', '2026-10-25T03:00:00'],
		['exactly then is tomorrow', '03:00', 'UTC', '2026-10-25T03:00:00', '2026-10-26T03:00:00'],
		['in New York', '03:00', 'America/New_York', '2026-07-01T06:00:00', '2026-07-01T07:00:00'],
		['British summer time', '03:00', 'Europe/London', '2026-07-01T00:00:00', '2026-07-01T02:00:00'],
		['after the clocks go back', '03:00', 'Europe/London', '2026-10-25T00:00:00', '2026-10-25T03:00:00'],
		['skipped by the clocks going forward', '01:30', 'Europe/London', '2026-03-29T00:00:00', '2026-03-29T01:30:00'],
		['the day after', '01:30', 'Europe/London', '2026-03-29T01:30:00', '2026-03-30T00:30:00']
	])('next run: %s', (_, time, zone, now, want) => {
		expect(nextRun({ enabled: true, time, time_zone: zone }, utc(now))?.toISOString()).toBe(utc(want).toISOString());
	});

	it('has no next run while off or invalid', () => {
		expect(nextRun({ enabled: false, time: '03:00', time_zone: 'UTC' }, new Date())).toBeNull();
		expect(nextRun({ enabled: true, time: '3am', time_zone: 'UTC' }, new Date())).toBeNull();
	});
});
