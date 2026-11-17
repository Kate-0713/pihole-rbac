// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Two-factor login (TOTP): the parts of it the pages share. Plain TypeScript, so it is tested without a browser.
import { ApiError, type Schemas } from '#lib/api/client.js';
import type { User } from '#lib/users.js';

export type TOTPStatus = Schemas['TOTPStatus'];
export type TOTPEnrolment = Schemas['TOTPEnrolment'];
export type TOTPPolicy = Schemas['TOTPPolicy'];

// The page a session is held to while its user must use two-factor login and hasn't turned it on.
export const setupPath = '/account/two-factor';

// Whether a refusal at the code step of a login means starting again from the password. A wrong code (totp_invalid)
// or a rate limit leaves the login waiting, so the code form stays. Anything else ends it: it ran out of time or
// attempts (login_expired), the account can no longer log in (invalid_credentials) or has no role (no_access). An
// error that isn't the server's (the network, say) says nothing about the login, so the code form stays for another
// try.
export function restartsLogin(e: unknown): boolean {
	if (!(e instanceof ApiError)) return false;
	return e.code === 'login_expired' || e.code === 'invalid_credentials' || e.code === 'no_access';
}

// groupSecret splits the base32 secret into groups of four, as authenticator apps show it, so it is easier to type.
// Apps ignore the spaces.
export function groupSecret(secret: string): string {
	return secret.match(/.{1,4}/g)?.join(' ') ?? '';
}

// codeReady says whether what was typed could be a code: six digits (spaces allowed, as apps show "123 456"), or,
// where recovery codes are accepted, something shaped like one (16 letters and digits, hyphens and spaces allowed).
// The server decides whether it is right.
export function codeReady(input: string, recovery: boolean): boolean {
	const compact = input.replace(/[\s-]/g, '');
	if (/^\d{6}$/.test(compact)) return true;
	return recovery && /^[a-z2-7]{16}$/i.test(compact);
}

// recoveryCodesFile is the text file a user downloads to keep their recovery codes. It says what they are for and
// for which account, since it may be found long after.
export function recoveryCodesFile(codes: readonly string[], username: string, at: Date, host: string): string {
	return [
		`pihole-rbac recovery codes for ${username} on ${host}`,
		`Made ${at.toISOString().slice(0, 16).replace('T', ' ')} UTC. Each works once, in place of a code from your`,
		'authenticator app. Getting new ones makes these stop working.',
		'',
		...codes,
		''
	].join('\n');
}

// policyLabel names a user's own setting, as the users page and its dialog show it.
export function policyLabel(p: TOTPPolicy): string {
	switch (p) {
		case 'required':
			return 'Required for this user';
		case 'exempt':
			return 'Not required for this user';
		default:
			return 'Follows their roles';
	}
}

// twoFactorSummary is the users table's two-factor column: whether it is on, and if not whether it ought to be.
export function twoFactorSummary(u: User): { label: string; tone: 'on' | 'missing' | 'off' } {
	if (u.totp_enabled) return { label: 'On', tone: 'on' };
	if (u.totp_required) return { label: 'Required, not set up', tone: 'missing' };
	return { label: 'Off', tone: 'off' };
}
