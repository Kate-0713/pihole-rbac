// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Personal API tokens: the parts the account page and the admin tab share. Plain TypeScript, so it is tested without a
// browser. The server checks every rule again.
import type { Schemas } from '#lib/api/client.js';
import type { Catalogue, PermissionInfo } from '#lib/roles.js';

export type APIToken = Schemas['APIToken'];
export type APITokenList = Schemas['APITokenList'];
export type APITokenInput = Schemas['APITokenInput'];
export type NewAPIToken = Schemas['NewAPIToken'];
export type TokenGrantable = Schemas['TokenGrantable'];

export const maxTokenNameChars = 64;

// canMakeTokens says whether the UI should offer to make a token: tokens.use, and a local account, since LDAP users
// can't have tokens until a later release (the server refuses them with ldap_user).
export function canMakeTokens(holdsTokensUse: boolean, source: string | undefined): boolean {
	return holdsTokensUse && source === 'local';
}

export const msgLDAPNoTokens = 'API tokens are only available to local accounts for now.';
export const maxLifetimeDays = 365;
const dayMs = 24 * 60 * 60 * 1000;

// The expiries the form offers, besides a date of the user's choosing.
export const expiryPresets = [
	{ days: 30, label: '30 days' },
	{ days: 90, label: '90 days' },
	{ days: 365, label: '1 year' }
] as const;

// tokenNameProblem returns what is wrong with a name, or null. Characters are counted as the server counts them (code
// points, not UTF-16 units), after trimming.
export function tokenNameProblem(name: string): string | null {
	const trimmed = name.trim();
	if (trimmed === '') return 'Give the token a name, such as the script or service that will use it.';
	if (Array.from(trimmed).length > maxTokenNameChars) return `Use at most ${maxTokenNameChars} characters.`;
	// eslint-disable-next-line no-control-regex
	if (/[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) return "The name can't contain control characters.";
	return null;
}

// presetExpiry is when a token made now with a preset expires.
export function presetExpiry(days: number, now: Date): Date {
	return new Date(now.getTime() + days * dayMs);
}

// dateExpiry turns a date input's value ("2027-03-01") into the end of that day in the browser's time zone, or null
// if it isn't a date.
export function dateExpiry(value: string): Date | null {
	const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
	if (!m) return null;
	const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 0);
	return d.getMonth() === Number(m[2]) - 1 ? d : null; // 2027-02-30 rolls over to March: not a date
}

// expiryProblem says what is wrong with an expiry, or null: it must be in the future and at most a year away.
export function expiryProblem(expires: Date | null, now: Date): string | null {
	if (!expires) return 'Choose a date.';
	if (expires.getTime() <= now.getTime()) return 'Choose a date in the future.';
	if (expires.getTime() - now.getTime() > maxLifetimeDays * dayMs) return 'A token can last at most a year.';
	return null;
}

// dateValue is a date as a date input holds it, in the browser's time zone: "2027-03-01".
export function dateValue(d: Date): string {
	return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

// maxDateValue is the latest date a date input should offer: a year from now, less a day so its end still fits.
export function maxDateValue(now: Date): string {
	return dateValue(new Date(now.getTime() + (maxLifetimeDays - 1) * dayMs));
}

// grantableCatalogue shapes what a token can hold as the role editor's catalogue, so its grant picker can be reused.
export function grantableCatalogue(g: TokenGrantable): Catalogue {
	return {
		permissions: g.permissions.map((p) => ({ name: p.name, class: p.class, description: p.description })),
		instances: g.instances,
		groups: g.groups
	};
}

// tokenScopes says where the picker offers a permission: only the scopes the user holds it at.
export function tokenScopes(
	g: TokenGrantable,
	p: PermissionInfo
): { all: boolean; instances: Catalogue['instances']; groups: Catalogue['groups'] } {
	const held = g.permissions.find((x) => x.name === p.name);
	if (!held) return { all: false, instances: [], groups: [] };
	return {
		all: held.all,
		instances: g.instances.filter((i) => held.instances.includes(i.id)),
		groups: g.groups.filter((x) => held.groups.includes(x.id))
	};
}

// stateLabel names a token's state for its badge.
export function stateLabel(t: APIToken): string {
	switch (t.state) {
		case 'active':
			return 'Active';
		case 'expired':
			return 'Expired';
		default:
			return 'Revoked';
	}
}

// expiresSoon is true for an active token that expires within a week, so the list can warn before a script breaks.
export function expiresSoon(t: APIToken, now: Date): boolean {
	return t.state === 'active' && new Date(t.expires_at).getTime() - now.getTime() < 7 * dayMs;
}

// curlExample is a command that tries a new token: the list of Pi-holes it can reach. The token goes in a header,
// never the URL, where proxies and shell history would keep it.
export function curlExample(token: string, origin: string): string {
	return `curl -H 'Authorization: Bearer ${token}' ${origin}/api/v1/targets`;
}
