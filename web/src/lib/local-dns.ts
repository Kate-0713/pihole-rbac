// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The Local DNS page's helpers: the server's rules for names, addresses, TTLs and reasons, checked as you type (the
// server checks them again), and how records and their states are put into words.
import { ApiError, type Schemas } from '#lib/api/client.js';

export type LocalDNS = Schemas['LocalDNS'];
export type DNSRecord = Schemas['DNSRecord'];
export type CNAMERecord = Schemas['CNAMERecord'];
export type LocalDNSInstance = Schemas['LocalDNSInstance'];
export type LocalDNSMark = Schemas['LocalDNSMark'];
export type LocalDNSKind = Schemas['LocalDNSKind'];

export const maxReason = 200;
export const maxTTL = 86400;

// One row of either table, so both can share a component: `name` is the hostname or alias, `points` the address or
// the target (with its TTL), and `extra` any further names an entry the app didn't write has.
export type Row = {
	kind: LocalDNSKind;
	key: string;
	value: string;
	name: string;
	points: string;
	extra: string[];
	ttl?: number;
	comment?: string;
	marks: LocalDNSMark[];
	reason?: Schemas['LocalDNSReason'];
};

export function recordRow(r: DNSRecord): Row {
	return {
		kind: 'record',
		key: r.key,
		value: r.value,
		name: r.hostnames[0] ?? r.value,
		points: r.ip ?? '',
		extra: r.hostnames.slice(1),
		comment: r.comment,
		marks: r.marks,
		reason: r.reason
	};
}

export function cnameRow(c: CNAMERecord): Row {
	return {
		kind: 'cname',
		key: c.key,
		value: c.value,
		name: c.aliases[0] ?? c.value,
		points: c.target ?? '',
		extra: c.aliases.slice(1),
		ttl: c.ttl,
		comment: c.comment,
		marks: c.marks,
		reason: c.reason
	};
}

// writable says whether the app could have written the entry, so it can be changed in place (an entry it couldn't
// can only be deleted, or replaced by one it can write).
export const writable = (r: Row) => r.marks.length === 0;

export const markLabel: Record<LocalDNSMark, string> = {
	multiple_names: 'Several names',
	comment: 'Comment',
	unparsed: "Doesn't parse"
};

export const markHint: Record<LocalDNSMark, string> = {
	multiple_names: 'Added outside the app with more than one name. The app only writes one name per entry.',
	comment: "Has a # comment, added outside the app. The app doesn't write comments.",
	unparsed:
		"Pi-hole's own check refuses this entry, so while it is there Pi-hole refuses every new entry of this kind. Delete it, or fix it in Pi-hole."
};

// nameProblem is the server's rule for a hostname, alias or target (localdns.CheckName), or null when it's fine.
export function nameProblem(name: string): string | null {
	const n = name.trim();
	if (n === '') return 'Enter a name.';
	if (n.length > 253) return 'The name is longer than 253 characters.';
	if (n.endsWith('.')) return "The name can't end with a dot.";
	if (/[^\x00-\x7f]/.test(n)) return 'Use letters, digits, hyphens and dots. An internationalised name needs its xn-- form.';
	if (/[^A-Za-z0-9.-]/.test(n)) return 'Use letters, digits, hyphens and dots only.';
	for (const label of n.split('.')) {
		if (label === '') return "The name can't have two dots together, or start with one.";
		if (label.length > 63) return 'A part of the name between dots is longer than 63 characters.';
		if (label.startsWith('-') || label.endsWith('-')) return "A part of the name can't start or end with a hyphen.";
	}
	return null;
}

const v4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

// ipProblem accepts an IPv4 address, or an IPv6 one without a zone, as Go's netip does.
export function ipProblem(ip: string): string | null {
	const a = ip.trim();
	if (a === '') return 'Enter an IPv4 or IPv6 address.';
	if (a.includes('%')) return "Pi-hole doesn't accept an address with a zone (%…).";
	if (v4.test(a)) return null;
	if (a.includes(':') && /^[0-9A-Fa-f:.]+$/.test(a) && validV6(a)) return null;
	return "That isn't a valid IPv4 or IPv6 address.";
}

// validV6 lets the browser's URL parser judge an IPv6 address, which it does by the standard.
function validV6(a: string): boolean {
	try {
		return new URL(`http://[${a}]/`).hostname !== '';
	} catch {
		return false;
	}
}

export function ttlProblem(ttl: string): string | null {
	const t = ttl.trim();
	if (t === '') return null;
	if (!/^\d+$/.test(t) || Number(t) > maxTTL) return `The TTL is a whole number of seconds, 0 to ${maxTTL}.`;
	return null;
}

export function reasonProblem(reason: string, required: boolean): string | null {
	const r = reason.trim();
	if (r === '' && required) return 'Give a reason for the change.';
	if ([...r].length > maxReason) return `The reason is longer than ${maxReason} characters.`;
	if (/[\x00-\x1f\x7f]/.test(r)) return "The reason can't contain line breaks.";
	return null;
}

// A name under a directory domain needs confirming: the domain, and which field it was, from the server's 409.
export function directoryConfirmation(e: unknown): { domain: string; field: string } | null {
	if (!(e instanceof ApiError) || e.code !== 'confirmation_required') return null;
	const domain = e.details.domain;
	return typeof domain === 'string' ? { domain, field: String(e.details.field ?? '') } : null;
}

// What an instance the app can't change needs, for the banner.
export function writableProblem(i: LocalDNSInstance): string | null {
	switch (i.writable) {
		case 'app_sudo_off':
			return `${i.instance} doesn't let the app change its local DNS: its webserver.api.app_sudo setting is off. An administrator can turn it on in Pi-hole's settings, or with: pihole-FTL --config webserver.api.app_sudo true`;
		case 'locked':
			return `${i.instance}'s config is read-only (misc.readOnly), so its local DNS can't be changed through its API.`;
		case 'unknown':
			return `${i.instance} couldn't be read, so whether its local DNS can be changed isn't known.`;
	}
	const locked = [i.records_locked ? 'records' : '', i.cnames_locked ? 'CNAMEs' : ''].filter((s) => s !== '');
	if (locked.length > 0) {
		return `${i.instance}'s ${locked.join(' and ')} are set by an environment variable, so Pi-hole won't let them be changed through its API.`;
	}
	return null;
}

// canChange says whether a target's entries of kind can be changed at all: an instance the app can't change, or
// whose entries of that kind are locked, can't. A mirrored group can always be tried: each member answers for itself.
export function canChange(d: Pick<LocalDNS, 'instances' | 'members'>, kind: LocalDNSKind): boolean {
	if (d.members) return true;
	const i = d.instances[0];
	if (!i || i.writable !== 'ok') return false;
	return kind === 'record' ? !i.records_locked : !i.cnames_locked;
}

// describe is how an entry is named in toasts and dialogs.
export function describe(r: Pick<Row, 'kind' | 'name' | 'points' | 'ttl'>): string {
	if (r.kind === 'record') return `${r.name} (${r.points})`;
	return `${r.name} → ${r.points}${r.ttl !== undefined ? `, TTL ${r.ttl}s` : ''}`;
}
