// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// can() answers "should the UI offer this?" from the permissions the server worked out for the session. It is for
// usability only: hiding a button protects nothing, and the server checks every request again.
import { session } from '#lib/stores/session.svelte.js';

// The permission catalogue, as in internal/rbac. Listed here only so a misspelt name is a type error; the server's
// catalogue is the source of truth.
export type GlobalPermission =
	| 'instances.manage'
	| 'settings.manage'
	| 'notifications.manage'
	| 'users.manage'
	| 'roles.manage'
	| 'sessions.manage'
	| 'audit.view'
	| 'config.reload'
	| 'app.update';

export type TargetPermission =
	| 'domains.view'
	| 'domains.edit'
	| 'clients.view'
	| 'clients.edit'
	| 'querylog.view'
	| 'blocking.toggle'
	| 'dns.restart'
	| 'clientreset.run'
	| 'drift.view'
	| 'drift.reconcile';

// can('users.manage') checks a global permission; can('domains.edit', 'i-1') checks one on a target. Reading
// session.current inside makes any component or $derived that calls this update when the session changes.
export function can(permission: GlobalPermission): boolean;
export function can(permission: TargetPermission, target: string | null | undefined): boolean;
export function can(permission: GlobalPermission | TargetPermission, target?: string | null): boolean {
	const perms = session.current?.permissions;
	if (!perms) return false;
	if (target === undefined) return perms.global.includes(permission);
	if (target === null) return false;
	return perms.targets[target]?.includes(permission) ?? false;
}

// canAny: the user holds at least one permission on the target, which is all the dashboard needs.
export function canAny(target: string | null | undefined): boolean {
	if (!target) return false;
	return (session.current?.permissions.targets[target]?.length ?? 0) > 0;
}

// canAnyGlobal: the user holds at least one of the given global permissions.
export function canAnyGlobal(...permissions: GlobalPermission[]): boolean {
	return permissions.some((p) => can(p));
}
