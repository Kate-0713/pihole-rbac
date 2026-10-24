// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Helpers for the domains page. The checks are browser-side copies of the server's (checkDomainKey and checkText in
// internal/api/targets.go), so a form can say what's wrong before it is sent. The server checks again, and Pi-hole
// checks what neither of them can: whether a domain or regex is valid at all.
import type { Schemas } from '#lib/api/client.js';

export type Domain = Schemas['Domain'];
export type PiholeGroup = Schemas['PiholeGroup'];
export type DomainType = Domain['type'];
export type DomainKind = Domain['kind'];

export const maxExactBytes = 255;
export const maxRegexBytes = 1024;
export const maxCommentChars = 500;

const bytes = (s: string) => new TextEncoder().encode(s).length;
// Control characters, line breaks included, as Go's unicode.IsControl sees them.
// eslint-disable-next-line no-control-regex
const control = /[\u0000-\u001f\u007f-\u009f]/;

// domainProblem returns what's wrong with a domain or regex as typed, or null. Surrounding spaces are ignored, as
// the server ignores them when adding.
export function domainProblem(domain: string, kind: DomainKind): string | null {
	const d = domain.trim();
	if (d === '') return 'Enter a domain.';
	const max = kind === 'regex' ? maxRegexBytes : maxExactBytes;
	if (bytes(d) > max) return `A ${kind === 'regex' ? 'regex' : 'domain'} can be at most ${max} bytes.`;
	if (control.test(d)) return "It can't contain control characters or line breaks.";
	return null;
}

// commentProblem returns what's wrong with a comment, or null.
export function commentProblem(comment: string): string | null {
	if ([...comment].length > maxCommentChars) return `A comment can be at most ${maxCommentChars} characters.`;
	if (control.test(comment)) return "A comment can't contain control characters or line breaks.";
	return null;
}

// groupNames names a list of group IDs, in the order of the Pi-hole's own list, with #<id> for a group it no longer
// lists.
export function groupNames(ids: readonly number[], groups: readonly PiholeGroup[]): string[] {
	const known = groups.filter((g) => ids.includes(g.id)).map((g) => g.name);
	const missing = ids.filter((id) => !groups.some((g) => g.id === id)).map((id) => `#${id}`);
	return [...known, ...missing];
}

// sameEntry says whether two entries are the same list entry: the same domain can be on both lists, and be both an
// exact and a regex entry.
export function sameEntry(a: Pick<Domain, 'domain' | 'type' | 'kind'>, b: Pick<Domain, 'domain' | 'type' | 'kind'>): boolean {
	return a.domain === b.domain && a.type === b.type && a.kind === b.kind;
}

// entryKey identifies an entry, for keyed {#each} blocks and test IDs.
export function entryKey(d: Pick<Domain, 'domain' | 'type' | 'kind'>): string {
	return `${d.type}/${d.kind}/${d.domain}`;
}

export const typeLabel: Record<DomainType, string> = { allow: 'Allow', deny: 'Deny' };
export const kindLabel: Record<DomainKind, string> = { exact: 'Exact', regex: 'Regex' };
