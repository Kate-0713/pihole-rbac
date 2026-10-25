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
	counts: { domains: 0, clients: 0, groups: 0 }
};

describe('summary', () => {
	it('says how the group stands', () => {
		expect(summary({ ...base, state: 'not_checked' })).toMatch(/^Not checked yet/);
		expect(summary({ ...base, state: 'primary_unavailable' })).toMatch(/primary couldn't be read/);
		expect(summary(base)).toBe('Every member that answered matches the primary.');
		expect(summary({ ...base, drifted: true, counts: { domains: 2, clients: 1, groups: 0 } })).toBe(
			'Members differ from the primary in 2 domain list entries and 1 client.'
		);
		expect(summary({ ...base, drifted: true, counts: { domains: 1, clients: 3, groups: 1 } })).toBe(
			'Members differ from the primary in 1 domain list entry, 3 clients and 1 Pi-hole group.'
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
			counts: { domains: 3, clients: 2, groups: 2 },
			domains: [
				{ instance: 'beta', instance_id: 2, domain: 'a', type: 'deny', kind: 'exact', difference: 'missing' },
				{ instance: 'beta', instance_id: 2, domain: 'b', type: 'deny', kind: 'exact', difference: 'missing' },
				{ instance: 'gamma', instance_id: 3, domain: 'c', type: 'deny', kind: 'exact', difference: 'extra' }
			],
			groups: [
				{ instance: 'beta', instance_id: 2, name: 'kids', difference: 'missing' },
				{ instance: 'gamma', instance_id: 3, name: 'own', difference: 'extra' }
			]
		};
		expect(plan(r)).toEqual({
			members: [
				{ member: 'beta', lines: ['Add 2 domain list entries', 'Create 1 Pi-hole group'] },
				{ member: 'gamma', lines: ['Delete 1 domain list entry'] }
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
