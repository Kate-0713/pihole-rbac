// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import {
	confirmationOf,
	countText,
	describeReference,
	hiddenCount,
	nameProblem,
	renameSummary,
	type GroupReference,
	type GroupReferences
} from './pihole-groups.js';

const refs = (rules: number, prot: number, items: GroupReferences['items'] = [], windows = 0): GroupReferences => ({
	counts: { client_reset_rules: rules, protected_groups: prot, group_windows: windows },
	items
});

describe('nameProblem', () => {
	it('accepts names Pi-hole would, spaces inside included', () => {
		expect(nameProblem('kids')).toBeNull();
		expect(nameProblem('school night')).toBeNull();
		expect(nameProblem('é'.repeat(255))).toBeNull();
	});
	it('refuses what the server refuses', () => {
		expect(nameProblem('')).toMatch(/Enter a name/);
		expect(nameProblem(' kids')).toMatch(/space/);
		expect(nameProblem('kids ')).toMatch(/space/);
		expect(nameProblem('a\nb')).toMatch(/control/);
		expect(nameProblem('a\tb')).toMatch(/control/);
		expect(nameProblem('x'.repeat(256))).toMatch(/255/);
	});
});

describe('confirmationOf', () => {
	it('reads the references and the Default flag of a confirmation', () => {
		const r = refs(1, 0);
		const c = confirmationOf(new ApiError(409, 'confirmation_required', 'Confirm.', { references: r }));
		expect(c).toEqual({ message: 'Confirm.', references: r, defaultGroup: false });
		expect(confirmationOf(new ApiError(409, 'confirmation_required', 'x', { default_group: true }))?.defaultGroup).toBe(true);
	});
	it('ignores other errors, and references that are not the right shape', () => {
		expect(confirmationOf(new ApiError(409, 'conflict', 'x'))).toBeNull();
		expect(confirmationOf(new Error('x'))).toBeNull();
		expect(confirmationOf(new ApiError(409, 'confirmation_required', 'x', { references: { counts: 2 } }))?.references).toBeNull();
	});
});

describe('describing references', () => {
	it('counts them in words', () => {
		expect(countText(refs(2, 1))).toBe('2 client reset rules and 1 protected group');
		expect(countText(refs(0, 3))).toBe('3 protected groups');
		expect(countText(refs(2, 1, [], 1))).toBe('2 client reset rules, 1 protected group and 1 schedule');
		expect(countText(refs(0, 0, [], 2))).toBe('2 schedules');
	});
	it('says how many the caller can not see', () => {
		const item: GroupReference = { kind: 'protected_group', scope: 'instance', scope_id: 1, scope_name: 'pihole1', names: ['kids'] };
		expect(hiddenCount(refs(2, 1, [item]))).toBe(2);
		expect(hiddenCount(refs(0, 1, [item], 2))).toBe(2);
	});
	it('names a reference', () => {
		expect(
			describeReference({ kind: 'client_reset_rule', scope: 'group', scope_id: 2, scope_name: 'site', comment_prefix: 'TEST-', match: 'names', names: ['kids', 'lab'] })
		).toBe('Client reset rule TEST- on group site, groups: kids, lab');
		expect(describeReference({ kind: 'protected_group', scope: 'instance', scope_id: 1, scope_name: 'pihole1', names: ['Kids'] })).toBe(
			'Protected group on pihole1: Kids'
		);
		expect(
			describeReference({ kind: 'group_window', scope: 'instance', scope_id: 1, scope_name: 'pihole1', schedule_name: 'Bedtime', schedule_kind: 'group_enabled', names: ['kids'] })
		).toBe('Schedule Bedtime on pihole1, enables: kids');
		expect(
			describeReference({ kind: 'group_window', scope: 'group', scope_id: 2, scope_name: 'site', schedule_name: 'Weekend', schedule_kind: 'group_disabled', names: ['strict'] })
		).toBe('Schedule Weekend on group site, disables: strict');
	});
	it('sums up a rename', () => {
		expect(renameSummary(undefined)).toBeNull();
		expect(renameSummary({ updated: refs(0, 0), to_check: refs(0, 0) })).toBeNull();
		expect(renameSummary({ updated: refs(1, 1), to_check: refs(1, 0) })).toBe(
			'References: 1 client reset rule and 1 protected group updated; 1 client reset rule to check.'
		);
		expect(renameSummary({ updated: refs(1, 0), to_check: refs(0, 0), error: 'Not updated.' })).toBe('Not updated.');
	});
});
