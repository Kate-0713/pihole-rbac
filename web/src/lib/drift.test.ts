// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { clientChanges, domainChanges, groupChanges, plan, reconcileSummary, summary, type DriftReport } from './drift.js';

const base: DriftReport = {
	group_id: 1,
	group: 'site',
	state: 'checked',
	drifted: false,
	members: [],
	counts: { domains: 0, clients: 0, groups: 0, lists: 0, local_dns: 0 }
};

describe('summary', () => {
	it('says how the group stands', () => {
		expect(summary({ ...base, state: 'not_checked' })).toMatch(/^Not checked yet/);
		expect(summary({ ...base, state: 'primary_unavailable' })).toMatch(/primary couldn't be read/);
		expect(summary(base)).toBe('Every member that answered matches the primary.');
		expect(summary({ ...base, drifted: true, counts: { domains: 2, clients: 1, groups: 0, lists: 0, local_dns: 0 } })).toBe(
			'Members differ from the primary in 2 domain list entries and 1 client.'
		);
		expect(summary({ ...base, drifted: true, counts: { domains: 1, clients: 3, groups: 1, lists: 2, local_dns: 0 } })).toBe(
			'Members differ from the primary in 1 domain list entry, 3 clients, 1 Pi-hole group and 2 subscribed lists.'
		);
		expect(summary({ ...base, drifted: true, counts: { domains: 0, clients: 0, groups: 0, lists: 0, local_dns: 1 } })).toBe(
			'Members differ from the primary in 1 local DNS entry.'
		);
	});
});

describe('changes', () => {
	const domain = {
		instance: 'beta',
		instance_id: 2,
		domain: 'games.example',
		type: 'deny' as const,
		kind: 'exact' as const,
		difference: 'changed' as const
	};
	it('lists what differs on an entry on both', () => {
		expect(
			domainChanges({
				...domain,
				primary: { comment: '', groups: ['kids'], enabled: true },
				member: { comment: 'old', groups: [], enabled: false }
			})
		).toEqual(['enabled → disabled', 'groups: kids → no groups', 'comment: none → "old"']);
		expect(domainChanges({ ...domain, difference: 'missing', primary: { comment: '', groups: [], enabled: true } })).toEqual([]);
	});

	it('does the same for clients and Pi-hole groups', () => {
		expect(
			clientChanges({
				instance: 'beta',
				instance_id: 2,
				client: '10.0.0.5',
				difference: 'changed',
				primary: { comment: 'tv', groups: ['Default'] },
				member: { comment: 'tv', groups: ['Default', 'kids'] }
			})
		).toEqual(['groups: Default → Default, kids']);
		expect(
			groupChanges({
				instance: 'beta',
				instance_id: 2,
				name: 'kids',
				difference: 'changed',
				primary: { comment: '', enabled: true },
				member: { comment: '', enabled: false }
			})
		).toEqual(['enabled → disabled']);
	});
});

describe('plan', () => {
	it('lists each member\'s changes, counting what the user can\'t see', () => {
		const r: DriftReport = {
			...base,
			drifted: true,
			counts: { domains: 3, clients: 2, groups: 2, lists: 4, local_dns: 0 },
			domains: [
				{ instance: 'beta', instance_id: 2, domain: 'a', type: 'deny', kind: 'exact', difference: 'missing' },
				{ instance: 'beta', instance_id: 2, domain: 'b', type: 'deny', kind: 'exact', difference: 'missing' },
				{ instance: 'gamma', instance_id: 3, domain: 'c', type: 'deny', kind: 'exact', difference: 'extra' }
			],
			groups: [
				{ instance: 'beta', instance_id: 2, name: 'kids', difference: 'missing' },
				{ instance: 'gamma', instance_id: 3, name: 'own', difference: 'extra' }
			],
			lists: [
				{ instance: 'beta', instance_id: 2, address: 'https://l.example/a', type: 'block', difference: 'changed' },
				{ instance: 'gamma', instance_id: 3, address: 'https://l.example/b', type: 'allow', difference: 'extra' },
				{ instance: 'gamma', instance_id: 3, address: 'https://l.example/c', type: 'block', difference: 'missing' },
				{ instance: 'gamma', instance_id: 3, address: 'https://l.example/d', type: 'block', difference: 'missing' }
			]
		};
		expect(plan(r)).toEqual({
			members: [
				{ member: 'beta', lines: ['Add 2 domain list entries', 'Change 1 subscribed list', 'Create 1 Pi-hole group'] },
				{ member: 'gamma', lines: ['Delete 1 domain list entry', 'Delete 1 subscribed list', 'Add 2 subscribed lists'] }
			],
			hidden: ['2 clients'],
			keptGroups: 1
		});
	});
});

describe('reconcileSummary', () => {
	it('counts what changed', () => {
		const report = { ...base };
		expect(reconcileSummary({ results: [], members: [], report })).toBe('Nothing needed changing.');
		expect(
			reconcileSummary({
				results: [
					{ instance: 'beta', instance_id: 2, item: 'domain', domain: 'a', action: 'add', status: 'ok' },
					{ instance: 'gamma', instance_id: 3, item: 'group', group: 'kids', action: 'add', status: 'ok' },
					{ instance: 'gamma', instance_id: 3, item: 'client', client: 'x', action: 'none', status: 'ok' }
				],
				members: [],
				report
			})
		).toBe('Reconciled 2 items on beta, gamma.');
	});
});

describe('plan without lists.view', () => {
	it("counts the lists it can't show", () => {
		const r: DriftReport = { ...base, drifted: true, counts: { domains: 0, clients: 0, groups: 0, lists: 3, local_dns: 0 } };
		expect(plan(r).hidden).toEqual(['3 subscribed lists']);
	});
});

describe('plan with local DNS', () => {
	it("adds and deletes entries, and leaves out those the app can't copy", () => {
		const entry = (instance: string, id: number, key: string, difference: 'missing' | 'extra', writable?: boolean) => ({
			instance,
			instance_id: id,
			record_kind: 'record' as const,
			key,
			value: key,
			difference,
			writable
		});
		const r: DriftReport = {
			...base,
			drifted: true,
			counts: { domains: 0, clients: 0, groups: 0, lists: 0, local_dns: 4 },
			local_dns: [
				entry('beta', 2, '10.0.0.5 nas.lab', 'missing', true),
				{ ...entry('beta', 2, 'a,b', 'missing', true), record_kind: 'cname' },
				entry('beta', 2, '10.0.0.6 a b', 'missing', false),
				entry('gamma', 3, '10.0.0.9 old', 'extra')
			]
		};
		expect(plan(r).members).toEqual([
			{ member: 'beta', lines: ['Add 2 local DNS entries', "Leave out 1 local DNS entry the app can't copy"] },
			{ member: 'gamma', lines: ['Delete 1 local DNS entry'] }
		]);
		expect(plan({ ...r, local_dns: undefined }).hidden).toEqual(['4 local DNS entries']);
	});
});
