// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The instance groups page's helpers: browser-side copies of the server's rules for a group's settings
// (GroupInput.normalize and checkGroup in internal/instances/groups.go), so the form can say what's wrong before it
// is sent. The server checks again, and alone knows about grants that stop a mirrored group becoming independent.
import type { Schemas } from '#lib/api/client.js';
import { nameProblem } from '#lib/instances.js';

export type Group = Schemas['InstanceGroup'];
export type GroupInput = Schemas['InstanceGroupInput'];
export type GroupMode = Group['mode'];

export const maxGroupMembers = 100;

export const modeLabel: Record<GroupMode, string> = {
	independent: 'Independent',
	mirrored: 'Mirrored'
};

export const modeDescription: Record<GroupMode, string> = {
	independent:
		'A label for organising instances. A permission granted on the group covers each member; changes still go to one instance at a time.',
	mirrored:
		'The members are run as one Pi-hole: domains, clients and groups are read from the primary, and changes go to every enabled member.'
};

// The form's state. primary is 0 when none is chosen.
export type GroupForm = { name: string; mode: GroupMode; members: number[]; primary: number };

export function emptyForm(): GroupForm {
	return { name: '', mode: 'independent', members: [], primary: 0 };
}

export function formFrom(g: Group): GroupForm {
	return {
		name: g.name,
		mode: g.mode,
		members: g.members.map((m) => m.id),
		primary: g.primary_instance_id ?? 0
	};
}

// toInput builds the request body: the primary is sent only for a mirrored group, as the server requires.
export function toInput(f: GroupForm): GroupInput {
	const members = [...new Set(f.members)].sort((a, b) => a - b);
	return {
		name: f.name.trim(),
		mode: f.mode,
		members,
		...(f.mode === 'mirrored' && f.primary !== 0 ? { primary_instance_id: f.primary } : {})
	};
}

// mirroredElsewhere maps each instance in a mirrored group other than `self` to that group's name. An instance can
// be in only one mirrored group, so these can't join another one.
export function mirroredElsewhere(groups: Group[], self: number | null): Map<number, string> {
	const out = new Map<number, string>();
	for (const g of groups) {
		if (g.mode !== 'mirrored' || g.id === self) continue;
		for (const m of g.members) out.set(m.id, g.name);
	}
	return out;
}

export type GroupProblems = { name: string | null; members: string | null; primary: string | null };

// groupProblems checks the form against the rules the server applies, given the other groups. `self` is the group
// being edited, or null while adding.
export function groupProblems(f: GroupForm, groups: Group[], self: number | null): GroupProblems {
	let name = nameProblem(f.name);
	if (name === null) {
		const taken = groups.find((g) => g.id !== self && g.name.toLowerCase() === f.name.trim().toLowerCase());
		if (taken) name = `There is already a group called "${taken.name}".`;
	}

	let members: string | null = null;
	if (f.members.length > maxGroupMembers) {
		members = `A group has at most ${maxGroupMembers} members.`;
	} else if (f.mode === 'mirrored') {
		const elsewhere = mirroredElsewhere(groups, self);
		const clash = f.members.find((id) => elsewhere.has(id));
		if (clash !== undefined) {
			members = `An instance can be in only one mirrored group, and one of these is already in "${elsewhere.get(clash)}".`;
		}
	}

	let primary: string | null = null;
	if (f.mode === 'mirrored') {
		if (f.members.length === 0) primary = 'A mirrored group needs at least one member, its primary.';
		else if (f.primary === 0 || !f.members.includes(f.primary)) primary = 'Choose the primary from the members.';
	}
	return { name, members, primary };
}

// sortedMembers lists a group's members for display: the primary first, then by name.
export function sortedMembers(g: Group): Group['members'] {
	return [...g.members].sort((a, b) => {
		if (a.id === g.primary_instance_id) return -1;
		if (b.id === g.primary_instance_id) return 1;
		return a.name.localeCompare(b.name);
	});
}

// formChanged says whether saving would change anything, ignoring member order and a primary an independent group
// doesn't use.
export function formChanged(before: GroupForm, after: GroupForm): boolean {
	const a = toInput(before);
	const b = toInput(after);
	return (
		a.name !== b.name ||
		a.mode !== b.mode ||
		a.primary_instance_id !== b.primary_instance_id ||
		a.members.join(',') !== b.members.join(',')
	);
}
