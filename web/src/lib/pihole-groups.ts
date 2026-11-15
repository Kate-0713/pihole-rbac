// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The Pi-hole groups page (not instance groups): the server's name rule, copied so a form can say what's wrong before
// it is sent, and how to read the app's references to a group from a 409 or a write's answer. The server checks
// everything again.
import { ApiError, type Schemas } from '#lib/api/client.js';
import { controlChars } from '#lib/pihole.js';

export type GroupReferences = Schemas['PiholeGroupReferences'];
export type GroupReference = Schemas['PiholeGroupReference'];
export type RenameReferences = Schemas['PiholeGroupRenameReferences'];
export type GroupUsage = Schemas['PiholeGroupUsage'];

// Pi-hole's Default group, ID 0 on every Pi-hole. Pi-hole doesn't protect it; the app refuses renaming or deleting
// it, and disabling it needs confirming.
export const defaultGroupID = 0;
export const maxGroupNameChars = 255;

// nameProblem returns what's wrong with a group name, or null: checkGroupName in internal/api/piholegroups.go.
export function nameProblem(name: string): string | null {
	if (name === '') return 'Enter a name.';
	if ([...name].length > maxGroupNameChars) return `A name can be at most ${maxGroupNameChars} characters.`;
	if (controlChars.test(name)) return "A name can't contain control characters or line breaks.";
	if (name.trim() !== name) return "A name can't start or end with a space.";
	return null;
}

// What a 409 confirmation_required for a Pi-hole group change carries: the references to the group, and whether the
// change disables the Default group. null when the error isn't such a 409. The details are untyped in the spec, so
// they're checked rather than trusted.
export type Confirmation = { message: string; references: GroupReferences | null; defaultGroup: boolean };

export function confirmationOf(e: unknown): Confirmation | null {
	if (!(e instanceof ApiError) || e.code !== 'confirmation_required') return null;
	const refs = e.details['references'];
	return {
		message: e.message,
		references: isReferences(refs) ? refs : null,
		defaultGroup: e.details['default_group'] === true
	};
}

function isReferences(x: unknown): x is GroupReferences {
	if (typeof x !== 'object' || x === null) return false;
	const r = x as Record<string, unknown>;
	const c = r.counts as Record<string, unknown> | undefined;
	return (
		typeof c === 'object' &&
		c !== null &&
		typeof c.client_reset_rules === 'number' &&
		typeof c.protected_groups === 'number' &&
		Array.isArray(r.items)
	);
}

export function referenceCount(refs: GroupReferences | null | undefined): number {
	return refs ? refs.counts.client_reset_rules + refs.counts.protected_groups + (refs.counts.group_windows ?? 0) : 0;
}

// countText says how many references there are: "2 client reset rules, 1 protected group and 1 schedule".
export function countText(refs: GroupReferences): string {
	const parts: string[] = [];
	const n = (k: number, one: string, many: string) => `${k} ${k === 1 ? one : many}`;
	if (refs.counts.client_reset_rules > 0) parts.push(n(refs.counts.client_reset_rules, 'client reset rule', 'client reset rules'));
	if (refs.counts.protected_groups > 0) parts.push(n(refs.counts.protected_groups, 'protected group', 'protected groups'));
	if ((refs.counts.group_windows ?? 0) > 0) parts.push(n(refs.counts.group_windows, 'schedule', 'schedules'));
	return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}` : (parts[0] ?? '');
}

// hiddenCount is how many references the caller can't see in full: they only see those they manage.
export function hiddenCount(refs: GroupReferences): number {
	return referenceCount(refs) - refs.items.length;
}

// describeReference names one reference in a line: "Client reset rule TEST- on pihole1: kids, lab".
export function describeReference(r: GroupReference): string {
	const where = `${r.scope === 'group' ? 'group ' : ''}${r.scope_name}`;
	if (r.kind === 'protected_group') return `Protected group on ${where}: ${r.names[0] ?? ''}`;
	if (r.kind === 'group_window') {
		const how = r.schedule_kind === 'group_disabled' ? 'disables' : 'enables';
		return `Schedule ${r.schedule_name ?? ''} on ${where}, ${how}: ${r.names[0] ?? ''}`;
	}
	const how = r.match === 'prefixes' ? 'prefixes' : 'groups';
	return `Client reset rule ${r.comment_prefix ?? ''} on ${where}, ${how}: ${r.names.join(', ')}`;
}

export const reasonText: Record<NonNullable<GroupReference['reason']>, string> = {
	prefix_match_changes: 'its prefixes now match only one of the two names',
	not_renamed_everywhere: "the rename didn't reach every instance it covers",
	old_name_still_used: 'another group there still matches it'
};

// renameSummary says in a sentence what a rename did to the references, or null when there were none.
export function renameSummary(refs: RenameReferences | undefined): string | null {
	if (!refs) return null;
	if (refs.error) return refs.error;
	const updated = referenceCount(refs.updated);
	const check = referenceCount(refs.to_check);
	if (updated === 0 && check === 0) return null;
	const parts: string[] = [];
	if (updated > 0) parts.push(`${countText(refs.updated)} updated`);
	if (check > 0) parts.push(`${countText(refs.to_check)} to check`);
	return `References: ${parts.join('; ')}.`;
}
