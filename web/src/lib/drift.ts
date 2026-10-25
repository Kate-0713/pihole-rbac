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

export type ReconcileResult = Schemas['ReconcileResult'];
export type ReconcileItemResult = Schemas['ReconcileItemResult'];

// A member's planned changes, for the "Reconcile all" confirmation: one line per kind of change.
export type MemberPlan = { member: string; lines: string[] };

const verb: Record<Difference, string> = { missing: 'add', changed: 'change', extra: 'delete' };

// plan says what "Reconcile all" will do, member by member, from the report: entries and clients added, changed or
// deleted, and Pi-hole groups created or changed (a group only a member has is kept). Types the user can't see are
// counted at the end, since the report has their numbers but not who they belong to.
export function plan(r: DriftReport): { members: MemberPlan[]; hidden: string[]; keptGroups: number } {
	const byMember = new Map<string, Map<string, number>>();
	const add = (member: string, line: string) => {
		const m = byMember.get(member) ?? new Map<string, number>();
		m.set(line, (m.get(line) ?? 0) + 1);
		byMember.set(member, m);
	};
	for (const d of r.domains ?? []) add(d.instance, `${verb[d.difference]}|domain list entry|domain list entries`);
	for (const c of r.clients ?? []) add(c.instance, `${verb[c.difference]}|client|clients`);
	let keptGroups = 0;
	for (const g of r.groups ?? []) {
		if (g.difference === 'extra') keptGroups++;
		else add(g.instance, `${g.difference === 'missing' ? 'create' : 'change'}|Pi-hole group|Pi-hole groups`);
	}
	const members = [...byMember].map(([member, lines]) => ({
		member,
		lines: [...lines].map(([line, n]) => {
			const [v, one, many] = line.split('|');
			return `${v[0].toUpperCase()}${v.slice(1)} ${n} ${n === 1 ? one : many}`;
		})
	}));
	const hidden: string[] = [];
	if (!r.domains && r.counts.domains > 0) hidden.push(count(r.counts.domains, 'domain list entry', 'domain list entries'));
	if (!r.clients && r.counts.clients > 0) hidden.push(count(r.counts.clients, 'client', 'clients'));
	return { members, hidden, keptGroups };
}

// reconcileKey is how an item result is named in a message: the entry, client or group.
export function reconcileKey(r: ReconcileItemResult): string {
	if (r.item === 'domain') return r.domain ?? '';
	if (r.item === 'client') return r.client ?? '';
	return `the ${r.group ?? ''} group`;
}

// reconcileSummary says what a reconcile did, for the success toast.
export function reconcileSummary(out: ReconcileResult): string {
	const changed = out.results.filter((r) => r.status === 'ok' && r.action !== 'none').length;
	if (changed === 0) return 'Nothing needed changing.';
	const members = new Set(out.results.filter((r) => r.status === 'ok' && r.action !== 'none').map((r) => r.instance));
	return `Reconciled ${changed} ${changed === 1 ? 'item' : 'items'} on ${[...members].join(', ')}.`;
}
