// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The DHCP page's helpers: the server's rules for addresses, lease times, settings and static leases (internal/dhcp),
// checked as you type (the server checks them again), and how leases and states are put into words.
import { ApiError, type Schemas } from '#lib/api/client.js';
import { nameProblem } from '#lib/local-dns.js';

export type DHCPSettings = Schemas['DHCPSettings'];
export type DHCPSettingsPatch = Schemas['DHCPSettingsPatch'];
export type DHCPInstance = Schemas['DHCPInstance'];
export type DHCPLease = Schemas['DHCPLease'];
export type DHCPLeaseSource = Schemas['DHCPLeaseSource'];
export type DHCPStaticLease = Schemas['DHCPStaticLease'];
export type DHCPStaticInstance = Schemas['DHCPStaticInstance'];
export type DHCPStaticMark = Schemas['DHCPStaticMark'];

// ---- addresses ----

// ipv4 reads a dotted-quad address into a number, or null. Like Go's netip it refuses leading zeros.
export function ipv4(text: string): number | null {
	const parts = text.trim().split('.');
	if (parts.length !== 4) return null;
	let n = 0;
	for (const p of parts) {
		if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
		n = n * 256 + Number(p);
	}
	return n;
}

// ipv4Problem is the server's rule for an address a device could be given or pointed at.
export function ipv4Problem(text: string): string | null {
	const n = ipv4(text);
	if (n === null) return "That isn't a valid IPv4 address.";
	if (n === 0 || n >>> 24 === 127 || n >>> 28 === 14 || n === 0xffffffff) return "That address can't be used by a device.";
	return null;
}

// maskBits is a netmask's prefix length, or -1 when it isn't a contiguous mask of 1 to 30 bits.
export function maskBits(text: string): number {
	const m = ipv4(text);
	if (m === null || m === 0) return -1;
	const inv = ~m >>> 0;
	if ((inv & (inv + 1)) !== 0) return -1;
	let bits = 0;
	for (let x = m; (x & 0x80000000) !== 0; x = (x << 1) >>> 0) bits++;
	return bits > 30 ? -1 : bits;
}

export type Subnet = { network: number; broadcast: number; bits: number; guessed: boolean };

// subnetOf is the subnet the settings serve: from the netmask, or, without one, from the class of the start address,
// as Pi-hole does. null when there is nothing to work it out from.
export function subnetOf(start: string, netmask: string): Subnet | null {
	const s = ipv4(start);
	if (s === null) return null;
	let bits = (s >>> 24) < 128 ? 8 : (s >>> 24) < 192 ? 16 : 24;
	let guessed = true;
	if (netmask.trim() !== '') {
		bits = maskBits(netmask);
		if (bits < 0) return null;
		guessed = false;
	}
	const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
	const network = (s & mask) >>> 0;
	return { network, broadcast: (network | ~mask) >>> 0, bits, guessed };
}

export const prefixText = (s: Subnet) => `${[24, 16, 8, 0].map((sh) => (s.network >>> sh) & 255).join('.')}/${s.bits}`;

// ---- lease time ----

const units: Record<string, number> = { '': 1, s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

// leaseTimeProblem is the server's rule: seconds, or a number with m, h, d or w, from 2 minutes to 365 days; empty
// keeps dnsmasq's default.
export function leaseTimeProblem(text: string): string | null {
	const t = text.trim().toLowerCase();
	if (t === '') return null;
	if (t === 'infinite') return "Infinite leases aren't allowed: an address would never come back from a device that has gone.";
	const m = /^(\d{1,9})([smhdw]?)$/.exec(t);
	if (!m) return 'Use a number of seconds, or a number followed by m, h, d or w (45m, 12h, 2d, 1w).';
	const seconds = Number(m[1]) * units[m[2]];
	if (seconds < 120) return 'The lease time must be at least 2 minutes.';
	if (seconds > 365 * 86400) return 'The lease time must be at most 365 days.';
	return null;
}

// ---- settings ----

export type SettingsForm = {
	active: boolean;
	start: string;
	end: string;
	router: string;
	netmask: string;
	lease_time: string;
	ipv6: boolean;
	rapid_commit: boolean;
	multi_dns: boolean;
	ignore_unknown_clients: boolean;
};

export type SettingsField = 'start' | 'end' | 'router' | 'netmask' | 'lease_time';

export const formOf = (s: DHCPSettings): SettingsForm => ({ ...s });

// settingsProblems checks the settings as they would be once saved, as Pi-hole does (internal/dhcp CheckSettings):
// the first problem of each field, by field.
export function settingsProblems(f: SettingsForm): Partial<Record<SettingsField, string>> {
	const out: Partial<Record<SettingsField, string>> = {};
	const lease = leaseTimeProblem(f.lease_time);
	if (lease) out.lease_time = lease;
	const addrs: Partial<Record<'start' | 'end' | 'router', number>> = {};
	for (const k of ['start', 'end', 'router'] as const) {
		if (f[k].trim() === '') {
			if (f.active) out[k] = 'This must be set while DHCP is on.';
			continue;
		}
		const p = ipv4Problem(f[k]);
		if (p) out[k] = p;
		else addrs[k] = ipv4(f[k]) as number;
	}
	if (f.netmask.trim() !== '' && maskBits(f.netmask) < 0) out.netmask = "That isn't a valid IPv4 netmask.";
	if (!f.active || Object.keys(out).length > 0) return out;
	const sub = subnetOf(f.start, f.netmask);
	if (!sub) return { ...out, netmask: "The subnet can't be worked out." };
	for (const k of ['start', 'end', 'router'] as const) {
		const a = addrs[k] as number;
		if (a < sub.network || a > sub.broadcast) out[k] = `The address isn't in the subnet ${prefixText(sub)}.`;
		else if (a === sub.network) out[k] = 'The address is the network address of the subnet.';
		else if (a === sub.broadcast) out[k] = 'The address is the broadcast address of the subnet.';
	}
	if (Object.keys(out).length > 0) return out;
	const [s, e, r] = [addrs.start as number, addrs.end as number, addrs.router as number];
	if (s > e) out.start = 'The start of the range is after its end.';
	else if (r >= s && r <= e) out.router = "The router's address is inside the range, which could hand it to a device.";
	return out;
}

// changedSettings is the patch that takes the current settings to the form's: only what differs.
export function changedSettings(cur: DHCPSettings, f: SettingsForm): DHCPSettingsPatch {
	const out: Record<string, string | boolean> = {};
	for (const k of Object.keys(cur) as (keyof DHCPSettings)[]) {
		const now = typeof f[k] === 'string' ? (f[k] as string).trim() : f[k];
		if (now !== cur[k]) out[k] = now;
	}
	return out as DHCPSettingsPatch;
}

// A change the server asks to confirm: what it lists, and which other instances already serve DHCP.
export type SettingsConfirmation = { summary: string[]; otherActive: string[] };

export function settingsConfirmation(e: unknown): SettingsConfirmation | null {
	if (!(e instanceof ApiError) || e.code !== 'confirmation_required') return null;
	const list = (v: unknown) => (Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : []);
	return { summary: list(e.details.summary), otherActive: list(e.details.other_active) };
}

// ---- static leases ----

// macProblem is the server's rule: six octets, with colons or hyphens, not a group address, not all zeros.
export function macProblem(text: string): string | null {
	const t = text.trim();
	if (!/^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(t)) return 'Use six pairs of hex digits, like aa:bb:cc:dd:ee:ff.';
	const octets = t.split(/[:-]/).map((o) => parseInt(o, 16));
	if ((octets[0] & 1) !== 0) return 'That is a group address, which no device has.';
	if (octets.every((o) => o === 0)) return 'The hardware address is all zeros.';
	return null;
}

// normalMac writes a hardware address as the server does: lowercase, with colons.
export const normalMac = (text: string) => text.trim().toLowerCase().replaceAll('-', ':');

// hostnameProblem: a static lease's hostname is optional and one label (no dots), and not a word dnsmasq would
// read as something else in a dhcp-host line.
export function hostnameProblem(text: string): string | null {
	const n = text.trim();
	if (n === '') return null;
	const p = nameProblem(n);
	if (p) return p;
	if (n.includes('.')) return 'Use a single name, with no dots.';
	const w = n.toLowerCase();
	if (w === 'ignore' || w === 'infinite' || /^\d+[smhdw]?$/.test(w)) return 'dnsmasq would read this as a lease time or option, not a name.';
	return null;
}

// staticIPProblem checks a static lease's address: IPv4, and inside the subnet DHCP serves when there is one.
export function staticIPProblem(text: string, subnet: string | null | undefined): string | null {
	const p = ipv4Problem(text);
	if (p) return p;
	const m = subnet ? /^(.+)\/(\d+)$/.exec(subnet) : null;
	if (!m) return null;
	const a = ipv4(text) as number;
	const bits = Number(m[2]);
	const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
	const network = ((ipv4(m[1]) as number) & mask) >>> 0;
	const broadcast = (network | ~mask) >>> 0;
	if (a < network || a > broadcast) return `The address isn't in the DHCP subnet ${subnet}.`;
	if (a === network || a === broadcast) return "The address is the subnet's network or broadcast address.";
	return null;
}

export const markLabel: Record<DHCPStaticMark, string> = {
	extra_fields: 'Extra fields',
	multiple_macs: 'Several MACs',
	ipv6: 'IPv6',
	no_mac: 'No MAC',
	unparsed: "Doesn't parse"
};

export const markHint: Record<DHCPStaticMark, string> = {
	extra_fields: 'Has a lease time, tag, client ID or ignore, added outside the app. The app only writes a MAC, an address and a name.',
	multiple_macs: 'Matches several hardware addresses, added outside the app.',
	ipv6: 'An IPv6 entry. The app only writes IPv4 static leases.',
	no_mac: "Has no hardware address (it matches by client ID or name), added outside the app.",
	unparsed: "The app can't read this entry. It can be deleted, or replaced by one the app writes."
};

// canChange says whether static leases can be changed here: an instance the app can't change, or whose static leases
// an environment variable sets, can't.
export function canChangeStatic(i: Pick<DHCPStaticInstance, 'writable' | 'locked'> | undefined): boolean {
	return !!i && i.writable === 'ok' && !i.locked;
}

// writableProblem is what an instance the app can't change needs, for the banner.
export function writableProblem(i: Pick<DHCPInstance, 'instance' | 'writable'>): string | null {
	switch (i.writable) {
		case 'app_sudo_off':
			return `${i.instance} doesn't let the app change its DHCP settings: its webserver.api.app_sudo setting is off. An administrator can turn it on in Pi-hole's settings, or with: pihole-FTL --config webserver.api.app_sudo true`;
		case 'locked':
			return `${i.instance}'s config is read-only (misc.readOnly), so its DHCP settings can't be changed through its API.`;
		case 'unknown':
			return `${i.instance} couldn't be read, so whether its DHCP settings can be changed isn't known.`;
	}
	return null;
}

// ---- leases ----

// expiryText: "Never" for a lease without an end, otherwise the time it ends and, for the next day or so, how long
// is left. `now` is in seconds.
export function expiryText(expires: number | undefined, now: number, locale?: string, timeZone?: string): string {
	if (!expires) return 'Never';
	const when = new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short', timeZone }).format(new Date(expires * 1000));
	const left = expires - now;
	if (left <= 0) return `${when} (ended)`;
	if (left < 90 * 60) return `${when} (${Math.ceil(left / 60)} min left)`;
	if (left < 36 * 3600) return `${when} (${Math.round(left / 3600)} h left)`;
	return when;
}

// canMakeStatic: an IPv4 lease with a hardware address, which isn't already a static lease on its instance.
export function canMakeStatic(l: Pick<DHCPLease, 'ipv6' | 'hwaddr' | 'ip'>, statics: readonly DHCPStaticLease[]): boolean {
	if (l.ipv6 || !l.hwaddr || macProblem(l.hwaddr) !== null) return false;
	const mac = normalMac(l.hwaddr);
	return !statics.some((s) => s.mac === mac || s.ip === l.ip);
}

// describeStatic is how a static lease is named in toasts and dialogs.
export const describeStatic = (mac: string, ip: string, hostname?: string) => `${hostname ? `${hostname} ` : ''}${ip} (${mac})`;
