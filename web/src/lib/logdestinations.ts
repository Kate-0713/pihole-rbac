// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The log forwarding page's helpers: browser-side copies of the server's rules for a destination (Input.Normalize in
// internal/logdestinations and Config.Validate in internal/syslogfwd), so the form can say what's wrong before it is
// sent, and the summaries the page shows. The server checks everything again.
import type { Schemas } from '#lib/api/client.js';
import { formatCount, formatDateTime } from '#lib/format.js';
import { controlChars } from '#lib/pihole.js';

export type LogDestination = Schemas['LogDestination'];
export type LogDestinationInput = Schemas['LogDestinationInput'];
export type LogTransport = Schemas['LogTransport'];
export type LogTLSMode = Schemas['LogTLSMode'];
export type LogState = LogDestination['status']['state'];

export const maxNameChars = 80;
export const maxHostChars = 253;
export const maxCAFileChars = 4096;

export const transportLabel: Record<LogTransport, string> = {
	tls: 'TLS',
	tcp: 'TCP, unencrypted',
	udp: 'UDP, unencrypted'
};

// The ports syslog collectors usually listen on, used until the port is typed.
export function defaultPort(t: LogTransport): number {
	return t === 'tls' ? 6514 : 514;
}

export function isPlain(t: LogTransport): boolean {
	return t === 'tcp' || t === 'udp';
}

export function nameProblem(name: string): string | null {
	const n = [...name.trim()].length;
	if (n === 0 || n > maxNameChars || controlChars.test(name.trim())) {
		return `A name is 1-${maxNameChars} characters, with no control characters.`;
	}
	return null;
}

// hostProblem follows validHost: a name or an address, with no scheme, port or spaces.
export function hostProblem(host: string): string | null {
	const h = host.trim();
	if (h === '' || h.length > maxHostChars) return `The host is 1-${maxHostChars} characters.`;
	const bad = 'Use a host name or an address, with no scheme, port or spaces.';
	if (h.includes(':')) return /^[0-9a-fA-F:.]+$/.test(h) && h.split(':').length > 2 ? null : bad;
	for (const label of h.split('.')) {
		if (label === '' || label.length > 63 || label.startsWith('-') || label.endsWith('-') || !/^[A-Za-z0-9_-]+$/.test(label)) {
			return bad;
		}
	}
	return null;
}

export function portProblem(port: string): string | null {
	const p = port.trim();
	if (!/^[0-9]{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535) return 'The port is a number from 1 to 65535.';
	return null;
}

// caFileProblem: an absolute path, at most 4096 characters. Empty is fine. It only applies to TLS with checking.
export function caFileProblem(path: string): string | null {
	const p = path.trim();
	if (p === '') return null;
	if (p.length > maxCAFileChars || controlChars.test(p)) return `The path is at most ${maxCAFileChars} characters, with no control characters.`;
	if (!p.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(p) && !p.startsWith('\\\\')) return 'Use an absolute path to a PEM file.';
	return null;
}

// What the form would save, for the rules below.
export type DestinationForm = {
	host: string;
	port: string;
	transport: LogTransport;
	tlsMode: LogTLSMode;
	caFile: string;
	enabled: boolean;
};

// needsPlainConfirm follows the server: a new destination, or a change of transport, to tcp or udp needs confirm=true.
export function needsPlainConfirm(d: LogDestination | null, transport: LogTransport): boolean {
	return isPlain(transport) && (d === null || d.transport !== transport);
}

// moved says whether the form sends the log somewhere else, or in another way, than the destination does now.
export function moved(d: LogDestination, f: DestinationForm): boolean {
	return (
		d.host !== f.host.trim() ||
		d.port !== Number(f.port) ||
		d.transport !== f.transport ||
		d.tls_mode !== (f.transport === 'tls' ? f.tlsMode : 'verify') ||
		(d.ca_file ?? '') !== (f.transport === 'tls' && f.tlsMode === 'verify' ? f.caFile.trim() : '')
	);
}

// guardWarnings says what the destination's current place will be sent when the form is saved, as the server's
// guards decide: it hears about the change, and is sent what it hadn't had. Nothing happens for a disabled one.
export function guardWarnings(d: LogDestination | null, f: DestinationForm): string[] {
	if (!d || !d.enabled) return [];
	const out: string[] = [];
	if (moved(d, f)) out.push('the log now goes somewhere else');
	if (!f.enabled) out.push('it was disabled');
	return out;
}

// where says where a destination sends, as host:port, with an IPv6 address in brackets.
export function where(d: LogDestination): string {
	const host = d.host.includes(':') ? `[${d.host}]` : d.host;
	return `${host}:${d.port}`;
}

export const stateLabel: Record<LogState, string> = {
	ok: 'Working',
	failing: 'Failing',
	disabled: 'Disabled',
	idle: 'Idle'
};

// errorText turns a failure code into a sentence. The server never sends text from the collector.
const errors: Record<string, string> = {
	invalid_config: 'the settings can’t be used',
	ca_file_invalid: 'the CA file couldn’t be read, or has no certificates in it',
	dial_failed: 'couldn’t connect',
	tls_failed: 'the TLS handshake failed',
	timeout: 'the collector didn’t answer in time',
	write_failed: 'sending failed',
	read_failed: 'couldn’t read the audit log',
	cursor_failed: 'couldn’t save its position',
	cursor_missing: 'its position is missing'
};

export function errorText(code: string | undefined): string {
	return (code && errors[code]) || 'sending failed';
}

// describeStatus lists the lines a destination shows under its name, most important first.
export function describeStatus(d: LogDestination): { text: string; problem: boolean }[] {
	const s = d.status;
	const out: { text: string; problem: boolean }[] = [];
	if (s.state === 'failing') {
		out.push({ text: `Failing since ${formatDateTime(s.failing_since)}: ${errorText(s.last_error)}.`, problem: true });
	}
	if (s.state !== 'disabled') {
		out.push({ text: s.last_sent_at ? `Last sent ${formatDateTime(s.last_sent_at)}.` : 'Nothing sent since the app started.', problem: false });
	}
	if (s.behind > 0) {
		out.push({ text: `${formatCount(s.behind)} ${s.behind === 1 ? 'entry' : 'entries'} still to send.`, problem: false });
	}
	if (s.skipped_pruned) {
		out.push({ text: `${formatCount(s.skipped_pruned)} deleted by the retention before they were sent.`, problem: true });
	}
	if (s.delivery === 'best_effort') {
		out.push({ text: 'UDP is best effort: nothing says whether a message arrived.', problem: false });
	}
	return out;
}

// toInput is the body that saves a destination as it is, with some fields changed: enabling or disabling from the
// menu sends the whole destination, as the API wants.
export function toInput(d: LogDestination, changes: Partial<LogDestinationInput> = {}): LogDestinationInput {
	const base: LogDestinationInput = {
		name: d.name,
		host: d.host,
		port: d.port,
		transport: d.transport,
		tls_mode: d.tls_mode,
		enabled: d.enabled
	};
	if (d.ca_file) base.ca_file = d.ca_file;
	return { ...base, ...changes };
}

// formInput is the body the form saves.
export function formInput(name: string, f: DestinationForm): LogDestinationInput {
	const tls = f.transport === 'tls';
	return {
		name: name.trim(),
		host: f.host.trim(),
		port: Number(f.port),
		transport: f.transport,
		tls_mode: tls ? f.tlsMode : 'verify',
		...(tls && f.tlsMode === 'verify' && f.caFile.trim() !== '' ? { ca_file: f.caFile.trim() } : {}),
		enabled: f.enabled
	};
}
