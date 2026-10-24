// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The instances page's helpers: browser-side copies of the server's rules for an instance's settings
// (Input.normalize in internal/instances/service.go and piholeapi.ParseBaseURL), so the form can say what's wrong
// before it is sent. The server checks again, and it alone can check that a CA file exists and parses.
import type { Schemas } from '#lib/api/client.js';
import { controlChars } from '#lib/pihole.js';

export type Instance = Schemas['Instance'];
export type InstanceInput = Schemas['InstanceInput'];
export type TLSMode = Instance['tls_mode'];

export const maxNameChars = 64;
export const maxBaseURLChars = 2048;
export const maxEnvNameChars = 64;
export const maxCAFileChars = 4096;

export const tlsModeLabel: Record<TLSMode, string> = {
	verify: 'Verify the certificate',
	insecure: "Don't verify (labs only)"
};

// passwordVariable is the variable an instance's password is read from, as secrets.InstanceVar builds it.
export function passwordVariable(envName: string): string {
	return `PIHOLE_RBAC_INSTANCE_${envName || '<ENV_NAME>'}_PASSWORD`;
}

// suggestEnvName turns a name into an env name: "Pi-hole 1" becomes "PI_HOLE_1". Only a suggestion for a new
// instance; the admin can change it.
export function suggestEnvName(name: string): string {
	return name
		.toUpperCase()
		.replace(/[^A-Z0-9]+/g, '_')
		.replace(/^_+|_+$/g, '')
		.slice(0, maxEnvNameChars);
}

export function nameProblem(name: string): string | null {
	const n = [...name.trim()].length;
	if (n === 0 || n > maxNameChars || controlChars.test(name.trim())) {
		return `A name is 1-${maxNameChars} characters, with no control characters.`;
	}
	return null;
}

export function envNameProblem(envName: string): string | null {
	const e = envName.trim();
	if (e.length === 0 || e.length > maxEnvNameChars || !/^[A-Z0-9_]+$/.test(e)) {
		return `Use 1-${maxEnvNameChars} characters of A-Z, 0-9 and _.`;
	}
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
	if (!inst.password_set) return { label: 'Password missing', tone: 'bad' };
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
			return 'The password variable is not set';
		case 'instance_misconfigured':
			return "The settings can't be used";
		default:
			return code;
	}
}

// toInput is the form's starting point for an existing instance.
export function toInput(inst: Instance): Required<InstanceInput> {
	return {
		name: inst.name,
		base_url: inst.base_url,
		env_name: inst.env_name,
		tls_mode: inst.tls_mode,
		ca_file: inst.ca_file ?? ''
	};
}

// connectionChanged says whether saving would change how an enabled instance connects, which the server only allows
// after a passing connection test.
export function connectionChanged(inst: Instance, input: InstanceInput): boolean {
	return (
		inst.base_url !== input.base_url.trim().replace(/\/+$/, '') ||
		inst.env_name !== input.env_name.trim() ||
		inst.tls_mode !== (input.tls_mode ?? 'verify') ||
		(inst.ca_file ?? '') !== (input.ca_file ?? '').trim()
	);
}
