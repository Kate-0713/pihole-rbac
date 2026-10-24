// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The LDAP page's helpers: the login-method choices, browser-side copies of the server's LDAP settings rules, the
// bind password rule, and readable results from the directory tools. Plain TypeScript, so it is tested without a
// browser. The server checks every rule again; these only shape what the page offers.
import type { Schemas } from '#lib/api/client.js';
import { formatDateTime } from '#lib/format.js';

export type LDAPView = Schemas['LDAPSettingsView'];
export type LDAPConnection = Schemas['LDAPConnection'];
export type Method = Schemas['LoginMethods']['methods'][number];
export type UserTest = Schemas['LDAPUserTest'];
export type GroupCheck = Schemas['LDAPGroupCheck'];
export type Mapping = Schemas['LDAPMapping'];

// MethodChoice is what the login-methods form edits: local is always on, so only LDAP and the order are choices.
export type MethodChoice = { ldap: boolean; ldapFirst: boolean };

export function toChoice(methods: readonly Method[]): MethodChoice {
	return { ldap: methods.includes('ldap'), ldapFirst: methods[0] === 'ldap' };
}

export function toMethods(c: MethodChoice): Method[] {
	if (!c.ldap) return ['local'];
	return c.ldapFirst ? ['ldap', 'local'] : ['local', 'ldap'];
}

export function sameMethods(a: readonly Method[], b: readonly Method[]): boolean {
	return a.length === b.length && a.every((m, i) => m === b[i]);
}

// The form's fields, as strings and a flag, before they are sent.
export type LDAPForm = {
	url: string;
	bind_dn: string;
	base_dn: string;
	user_filter: string;
	tls_mode: 'verify' | 'insecure';
	allow_cn_fallback: boolean;
};

export function toForm(s: LDAPConnection | undefined): LDAPForm {
	return {
		url: s?.url ?? '',
		bind_dn: s?.bind_dn ?? '',
		base_dn: s?.base_dn ?? '',
		user_filter: s?.user_filter ?? '(uid=%s)',
		tls_mode: s?.tls_mode ?? 'verify',
		allow_cn_fallback: s?.allow_cn_fallback ?? false
	};
}

// Hints for the form's fields, keyed by the server's field names; null where a field is fine.
export function formProblems(f: LDAPForm): Record<'url' | 'bind_dn' | 'base_dn' | 'user_filter', string | null> {
	const url = f.url.trim();
	let urlProblem: string | null = null;
	try {
		const u = new URL(url);
		const scheme = u.protocol === 'ldap:' || u.protocol === 'ldaps:';
		if (!scheme || u.hostname === '' || (u.pathname !== '' && u.pathname !== '/')) {
			urlProblem = 'Use ldaps://host or ldap://host, with an optional :port.';
		}
	} catch {
		urlProblem = 'Use ldaps://host or ldap://host, with an optional :port.';
	}
	const dn = (v: string, what: string) =>
		/^[^=,]+=[^,]/.test(v.trim()) ? null : `Enter the ${what}, such as cn=svc,dc=example,dc=com.`;
	const filter = f.user_filter.trim();
	const percents = (filter.match(/%/g) ?? []).length;
	const filterProblem =
		filter.split('%s').length !== 2 || percents !== 1 || !filter.startsWith('(') || !filter.endsWith(')')
			? 'Use a filter in brackets with %s exactly once where the username goes, such as (uid=%s).'
			: null;
	return {
		url: urlProblem,
		bind_dn: dn(f.bind_dn, 'bind DN'),
		base_dn: dn(f.base_dn, 'base DN'),
		user_filter: filterProblem
	};
}

export function plainLDAP(url: string): boolean {
	return url.trim().toLowerCase().startsWith('ldap://');
}

// serverChanged says whether saving would send the bind password somewhere it wasn't entered for: the first save, a
// new URL, or a change to how the server's certificate is trusted. Mirrors the server's rule.
export function serverChanged(saved: LDAPConnection | undefined, f: LDAPForm): boolean {
	if (!saved) return true;
	return (
		saved.url.toLowerCase() !== f.url.trim().toLowerCase() ||
		saved.tls_mode !== f.tls_mode ||
		saved.allow_cn_fallback !== f.allow_cn_fallback
	);
}

// needsPassword says whether the form must ask for the bind password before saving.
export function needsPassword(view: LDAPView, f: LDAPForm): boolean {
	return view.bind_password.source !== 'none' && serverChanged(view.settings, f);
}

// passwordStatus describes where the bind password comes from, for the line under the field.
export function passwordStatus(view: LDAPView): string {
	const pw = view.bind_password;
	switch (pw.source) {
		case 'environment':
			return `From ${pw.variable}, which overrides a stored password.`;
		case 'stored':
			if (!pw.updated_at) return 'Stored. Leave the field empty to keep it.';
			return `Stored, changed ${formatDateTime(pw.updated_at)}${pw.updated_by ? ` by ${pw.updated_by}` : ''}. Leave the field empty to keep it.`;
		default:
			return 'Not set.';
	}
}

// groupCheckLabel says what the directory said about a group.
export function groupCheckLabel(c: GroupCheck): string {
	if (!c.exists) return "The directory has no such group. Check the DN; a mapping to it gives nobody the role.";
	return `The group exists, with ${c.members} member${c.members === 1 ? '' : 's'}.`;
}

// testVerdict sums up a user test in one line.
export function testVerdict(t: UserTest): { tone: 'ok' | 'bad'; text: string } {
	if (t.local_account) {
		return { tone: 'bad', text: `${t.username} is a local account, so an LDAP login with that name is refused.` };
	}
	if (!t.found) {
		return { tone: 'bad', text: `The directory has no single entry for ${t.username}, so they can't log in through LDAP.` };
	}
	if (t.roles.length === 0) {
		return { tone: 'bad', text: `None of ${t.username}'s groups is mapped to a role, so their login would be refused.` };
	}
	return { tone: 'ok', text: `${t.username} would log in with: ${t.roles.map((r) => r.name).join(', ')}.` };
}

// matchedGroups is the set of the user's groups that a mapping matched, compared as the server compares DNs only
// roughly: ignoring case and spaces after commas. Only used to highlight rows.
export function matchedGroups(t: UserTest): Set<string> {
	const norm = (dn: string) => dn.toLowerCase().replace(/,\s+/g, ',').trim();
	const mapped = new Set(t.mappings.map((m) => norm(m.group_dn)));
	return new Set(t.groups.filter((g) => mapped.has(norm(g))));
}
