// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The roles pages' helpers: the grant editor's state, which scopes each permission allows, readable summaries of a
// role's grants, and spotting a request that needs confirming. Plain TypeScript, so it is tested without a browser.
// The server checks every rule again; these only shape what the page offers.
import { ApiError, type Schemas } from '#lib/api/client.js';
import { controlChars } from '#lib/pihole.js';

export type Role = Schemas['Role'];
export type Grant = Schemas['Grant'];
export type Catalogue = Schemas['RoleCatalogue'];
export type PermissionInfo = Schemas['PermissionInfo'];
export type PermissionClass = PermissionInfo['class'];

export const maxRoleNameChars = 64;
export const maxDescriptionChars = 500;

export const classLabel: Record<PermissionClass, string> = {
	instance: 'On instances',
	group: 'On mirrored groups',
	global: 'Administration'
};

export function roleNameProblem(name: string): string | null {
	const n = [...name.trim()].length;
	if (n === 0 || n > maxRoleNameChars || controlChars.test(name.trim())) {
		return `A role name is 1-${maxRoleNameChars} characters, with no control characters.`;
	}
	return null;
}

export function descriptionProblem(description: string): string | null {
	if ([...description.trim()].length > maxDescriptionChars) {
		return `A description is at most ${maxDescriptionChars} characters.`;
	}
	// Line breaks and tabs are allowed in a description; other control characters aren't.
	if (/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(description)) {
		return "A description can't contain control characters.";
	}
	return null;
}

// PermissionScopes is one row of the grant editor: where a permission is granted. `all` covers everything, so the
// lists are ignored while it is set (but kept, so unticking All brings them back).
export type PermissionScopes = { all: boolean; instances: number[]; groups: number[] };

// EditorState maps each permission name to its row.
export type EditorState = Record<string, PermissionScopes>;

const emptyRow = (): PermissionScopes => ({ all: false, instances: [], groups: [] });

// toState fills the editor from a role's grants, with a row for every permission in the catalogue.
export function toState(grants: readonly Grant[], catalogue: Catalogue): EditorState {
	const state: EditorState = {};
	for (const p of catalogue.permissions) state[p.name] = emptyRow();
	for (const g of grants) {
		const row = (state[g.permission] ??= emptyRow());
		if (g.scope === 'all') row.all = true;
		else if (g.scope === 'instance' && g.id !== undefined) row.instances.push(g.id);
		else if (g.scope === 'group' && g.id !== undefined) row.groups.push(g.id);
	}
	return state;
}

// toGrants turns the editor back into grants: `all` alone when it is set, otherwise one grant per instance and group.
// The order is stable (catalogue order, then IDs), which makes comparing two lists simple.
export function toGrants(state: EditorState, catalogue: Catalogue): Grant[] {
	const out: Grant[] = [];
	const names = [...catalogue.permissions.map((p) => p.name), ...Object.keys(state).filter((n) => !catalogue.permissions.some((p) => p.name === n))];
	for (const name of names) {
		const row = state[name];
		if (!row) continue;
		if (row.all) {
			out.push({ permission: name, scope: 'all' });
			continue;
		}
		for (const id of [...row.instances].sort((a, b) => a - b)) out.push({ permission: name, scope: 'instance', id });
		for (const id of [...row.groups].sort((a, b) => a - b)) out.push({ permission: name, scope: 'group', id });
	}
	return out;
}

const grantKey = (g: Grant) => `${g.permission}|${g.scope}|${g.id ?? ''}`;

// sameGrants compares two grant lists, ignoring order and duplicates.
export function sameGrants(a: readonly Grant[], b: readonly Grant[]): boolean {
	const ka = new Set(a.map(grantKey));
	const kb = new Set(b.map(grantKey));
	return ka.size === kb.size && [...ka].every((k) => kb.has(k));
}

// scopeOptions says what the editor offers for a permission, following the catalogue's classes: an instance
// permission can be granted on any instance or group, a group permission on mirrored groups only, and a global one
// at scope all only.
export function scopeOptions(p: PermissionInfo, catalogue: Catalogue): { instances: Catalogue['instances']; groups: Catalogue['groups'] } {
	switch (p.class) {
		case 'instance':
			return { instances: catalogue.instances, groups: catalogue.groups };
		case 'group':
			return { instances: [], groups: catalogue.groups.filter((g) => g.mode === 'mirrored') };
		default:
			return { instances: [], groups: [] };
	}
}

// scopeName names a grant's scope: "all instances", an instance's name, or "group <name>".
export function scopeName(g: Grant, catalogue: Catalogue): string {
	if (g.scope === 'all') return 'all instances';
	if (g.scope === 'instance') return catalogue.instances.find((i) => i.id === g.id)?.name ?? `instance #${g.id}`;
	const group = catalogue.groups.find((x) => x.id === g.id);
	return group ? `group ${group.name}` : `group #${g.id}`;
}

// summarise lists a role's grants for the table, one line per permission: "domains.edit: pihole1, pihole2". Global
// permissions have no scope to name. Without the catalogue (a user who can't read it), IDs are shown.
export function summarise(grants: readonly Grant[], catalogue: Catalogue | null): string[] {
	const byPermission = new Map<string, string[]>();
	for (const g of grants) {
		const list = byPermission.get(g.permission) ?? [];
		list.push(
			catalogue
				? scopeName(g, catalogue)
				: g.scope === 'all'
					? 'all instances'
					: `${g.scope} #${g.id}`
		);
		byPermission.set(g.permission, list);
	}
	const isGlobal = (name: string) => catalogue?.permissions.find((p) => p.name === name)?.class === 'global';
	return [...byPermission].map(([name, scopes]) => (isGlobal(name) ? name : `${name}: ${scopes.join(', ')}`));
}

// The answer to a change that would take away the caller's own access: 409 confirmation_required, with what would be
// lost in details.would_lose. The page asks, then repeats the request with ?confirm=true.
export function needsConfirmation(e: unknown): e is ApiError {
	return e instanceof ApiError && e.code === 'confirmation_required';
}

// wouldLose reads details.would_lose: a list of permissions, or "account" when the change is to one's own account.
export function wouldLose(e: ApiError): string[] {
	const v = e.details.would_lose;
	if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
	if (typeof v === 'string') return [v];
	return [];
}
