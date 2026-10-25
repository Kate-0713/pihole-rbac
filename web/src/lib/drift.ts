// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The drift page's helpers: how a mirrored group's differences are put into words. A difference compares one member
// with the primary, the group's source of truth.
import type { Schemas } from '#lib/api/client.js';

export type DriftReport = Schemas['DriftReport'];
export type DomainDrift = Schemas['DomainDrift'];
export type ClientDrift = Schemas['ClientDrift'];
export type PiholeGroupDrift = Schemas['PiholeGroupDrift'];
export type Difference = Schemas['DriftDifference'];

export const differenceLabel: Record<Difference, string> = {
	missing: 'Missing',
	extra: 'Only here',
	changed: 'Different'
};

// What each difference means, said from the member's side.
export const differenceHint: Record<Difference, string> = {
	missing: 'On the primary, not on this member',
	extra: 'On this member, not on the primary',
	changed: 'On both, with different settings'
};

const groupList = (groups: string[]) => (groups.length === 0 ? 'no groups' : groups.join(', '));

// changes lists what differs between the primary's and a member's settings of an item on both, as "what: primary →
// member" phrases, so the page can say exactly what to look at.
export function domainChanges(d: DomainDrift): string[] {
	if (!d.primary || !d.member) return [];
	const out: string[] = [];
	if (d.primary.enabled !== d.member.enabled) {
		out.push(`${d.primary.enabled ? 'enabled' : 'disabled'} → ${d.member.enabled ? 'enabled' : 'disabled'}`);
	}
	if (d.primary.groups.join('\n') !== d.member.groups.join('\n')) {
		out.push(`groups: ${groupList(d.primary.groups)} → ${groupList(d.member.groups)}`);
	}
	if (d.primary.comment !== d.member.comment) out.push(`comment: ${quote(d.primary.comment)} → ${quote(d.member.comment)}`);
	return out;
}

export function clientChanges(c: ClientDrift): string[] {
	if (!c.primary || !c.member) return [];
	const out: string[] = [];
	if (c.primary.groups.join('\n') !== c.member.groups.join('\n')) {
		out.push(`groups: ${groupList(c.primary.groups)} → ${groupList(c.member.groups)}`);
	}
	if (c.primary.comment !== c.member.comment) out.push(`comment: ${quote(c.primary.comment)} → ${quote(c.member.comment)}`);
	return out;
}

export function groupChanges(g: PiholeGroupDrift): string[] {
	if (!g.primary || !g.member) return [];
	const out: string[] = [];
	if (g.primary.enabled !== g.member.enabled) {
		out.push(`${g.primary.enabled ? 'enabled' : 'disabled'} → ${g.member.enabled ? 'enabled' : 'disabled'}`);
	}
	if (g.primary.comment !== g.member.comment) out.push(`comment: ${quote(g.primary.comment)} → ${quote(g.member.comment)}`);
	return out;
}

function quote(s: string): string {
	return s === '' ? 'none' : `"${s}"`;
}

// summary says in a sentence how the group stands.
export function summary(r: DriftReport): string {
	switch (r.state) {
		case 'not_checked':
			return "Not checked yet since the server started. It's checked every few minutes, or now with Check now.";
		case 'primary_unavailable':
			return "The primary couldn't be read, so the members couldn't be compared with it.";
	}
	if (!r.drifted) return 'Every member that answered matches the primary.';
	const parts = [
		count(r.counts.domains, 'domain list entry', 'domain list entries'),
		count(r.counts.clients, 'client', 'clients'),
		count(r.counts.groups, 'Pi-hole group', 'Pi-hole groups')
	].filter((p) => p !== '');
	return `Members differ from the primary in ${joinAnd(parts)}.`;
}

function count(n: number, one: string, many: string): string {
	return n === 0 ? '' : `${n} ${n === 1 ? one : many}`;
}

function joinAnd(parts: string[]): string {
	return parts.length <= 1 ? (parts[0] ?? '') : `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`;
}
