// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The instances page's helpers: browser-side copies of the server's rules for an instance's settings
// (Input.normalize in internal/instances/service.go and piholeapi.ParseBaseURL), so the form can say what's wrong
// before it is sent. The server checks again, and it alone can check that a CA file exists and parses.
import type { Schemas } from '#lib/api/client.js';
import { formatDateTime } from '#lib/format.js';
import { controlChars } from '#lib/pihole.js';

export type Instance = Schemas['Instance'];
export type InstanceInput = Schemas['InstanceInput'];
export type TLSMode = Instance['tls_mode'];

export const maxNameChars = 64;
export const maxBaseURLChars = 2048;
export const maxEnvNameChars = 64;
export const maxCAFileChars = 4096;
export const maxPasswordBytes = 1024;

export const tlsModeLabel: Record<TLSMode, string> = {
	verify: 'Verify the certificate',
	insecure: "Don't verify (labs only)"
};

// passwordVariable is the variable whose password overrides an instance's stored one, as secrets.InstanceVar builds
// it.
export function passwordVariable(envName: string): string {
	return `PIHOLE_RBAC_INSTANCE_${envName || '<ENV_NAME>'}_PASSWORD`;
}

export function nameProblem(name: string): string | null {
	const n = [...name.trim()].length;
	if (n === 0 || n > maxNameChars || controlChars.test(name.trim())) {
		return `A name is 1-${maxNameChars} characters, with no control characters.`;
	}
	return null;
}

// envNameProblem checks the optional env name: empty, or up to 64 characters of A-Z, 0-9 and _.
export function envNameProblem(envName: string): string | null {
	const e = envName.trim();
	if (e.length > maxEnvNameChars || !/^[A-Z0-9_]*$/.test(e)) {
		return `Leave it empty, or use up to ${maxEnvNameChars} characters of A-Z, 0-9 and _.`;
	}
	return null;
}

// passwordProblem checks a password about to be sent: 1-1024 bytes, used exactly as typed, and typed the same twice.
export function passwordProblem(password: string, repeated: string): string | null {
	if (password === '') return 'Enter the password.';
	if (new TextEncoder().encode(password).length > maxPasswordBytes) {
		return `A password can be at most ${maxPasswordBytes} bytes.`;
	}
	if (password !== repeated) return "The two passwords don't match.";
	return null;
}

// baseURLProblem follows piholeapi.ParseBaseURL. The browser's URL parser is a little more forgiving than Go's, so a
// URL it accepts can still be refused by the server, whose message is then shown.
export function baseURLProblem(baseURL: string): string | null {
	const s = baseURL.trim();
	if (s.length === 0) return 'Enter the Pi-hole\'s address, such as https://pihole1.lan.';
	if (s.length > maxBaseURLChars) return `A base URL is at most ${maxBaseURLChars} characters.`;
	if (!/^https?:\/\//i.test(s)) return 'The base URL must start with http:// or https://.';
	let u: URL;
	try {
		u = new URL(s);
	} catch {
		return "That isn't a valid URL.";
	}
	if (!u.hostname) return 'The base URL has no host.';
	if (u.username || u.password) return "The base URL can't contain a username or password.";
	if (u.search || u.hash || s.includes('?') || s.includes('#')) return "The base URL can't have a query or fragment.";
	const path = u.pathname.replace(/\/+$/, '').toLowerCase();
	if (path.endsWith('/admin') || path.endsWith('/api')) {
		return "Use the Pi-hole's address without /admin or /api.";
	}
	return null;
}

// isHTTPS says whether a base URL uses https, which a CA file needs.
export function isHTTPS(baseURL: string): boolean {
	return /^https:\/\//i.test(baseURL.trim());
}

// caFileProblem checks what the browser can: the server also checks that the file exists and holds certificates.
export function caFileProblem(caFile: string, tlsMode: TLSMode, baseURL: string): string | null {
	const f = caFile.trim();
	if (f === '') return null;
	if (f.length > maxCAFileChars) return `A CA file path is at most ${maxCAFileChars} characters.`;
	if (tlsMode !== 'verify') return 'A CA file can only be used when the certificate is verified.';
	if (!isHTTPS(baseURL)) return 'A CA file only applies to an https:// base URL.';
	// An absolute path on the server, which runs on Linux; a Windows path is accepted for development there.
	if (!f.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(f)) return 'The CA file must be an absolute path on the server.';
	return null;
}

// Status is what the table shows about an instance at a glance.
export type Status = { label: string; tone: 'ok' | 'bad' | 'muted' };

export function instanceStatus(inst: Instance): Status {
	if (!inst.enabled) return { label: 'Disabled', tone: 'muted' };
	if (!inst.password_set) return { label: 'No password', tone: 'bad' };
	switch (inst.health?.state) {
		case 'up':
			return { label: 'Up', tone: 'ok' };
		case 'down':
			return { label: 'Down', tone: 'bad' };
		default:
			return { label: 'Not checked yet', tone: 'muted' };
	}
}

// errorLabel names the error codes in an instance's health and test results.
export function errorLabel(code: string | undefined): string | null {
	switch (code) {
		case undefined:
		case '':
			return null;
		case 'pihole_unreachable':
			return "Pi-hole didn't respond";
		case 'pihole_auth_rejected':
			return 'Pi-hole refused the password';
		case 'pihole_status_error':
			return 'Pi-hole answered with an error';
		case 'instance_password_missing':
			return 'It has no password';
		case 'instance_misconfigured':
			return "The settings can't be used";
		default:
			return code;
	}
}

// The fields of the instance form that decide where an instance connects and which password it uses.
export type Connection = { base_url: string; env_name: string; tls_mode: TLSMode; ca_file: string };

// addressChanged says whether saving would send the instance's password somewhere new: another base URL, TLS mode
// or CA file. The server then wants the password again (see needsPassword).
export function addressChanged(inst: Instance, c: Connection): boolean {
	return (
		inst.base_url !== c.base_url.trim().replace(/\/+$/, '') ||
		inst.tls_mode !== c.tls_mode ||
		(inst.ca_file ?? '') !== c.ca_file.trim()
	);
}

// connectionChanged says whether saving would change how an enabled instance connects, which the server only allows
// after a passing connection test.
export function connectionChanged(inst: Instance, c: Connection): boolean {
	return addressChanged(inst, c) || (inst.env_name ?? '') !== c.env_name.trim();
}

// needsPassword says whether an edit must give the password again: a password is only sent to an address it was
// confirmed for. The server also wants it when the instance starts using an env variable that is set, which only it
// can know; the form then asks for it after the first try.
export function needsPassword(inst: Instance, c: Connection): boolean {
	return inst.password_set && addressChanged(inst, c);
}

// passwordSummary says where an instance's password comes from, for the table.
export function passwordSummary(inst: Instance): { label: string; tone: 'ok' | 'bad'; detail: string | null } {
	switch (inst.password_source) {
		case 'stored':
			return {
				label: 'Stored',
				tone: 'ok',
				detail: inst.password_updated_at
					? `Changed ${formatDateTime(inst.password_updated_at)}${inst.password_updated_by ? ` by ${inst.password_updated_by}` : ''}`
					: null
			};
		case 'environment':
			return { label: 'Environment', tone: 'ok', detail: inst.password_variable ?? null };
		default:
			return { label: 'Missing', tone: 'bad', detail: inst.password_variable ? `Store one, or set ${inst.password_variable}` : null };
	}
}
