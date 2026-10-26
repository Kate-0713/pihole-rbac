// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The System page's helpers: versions, update requests, secrets and the update banner's rules. Plain TypeScript, so
// it is tested without a browser. The server checks everything again.
import type { Schemas } from '#lib/api/client.js';

export type VersionInfo = Schemas['VersionInfo'];
export type UpdateStatus = Schemas['UpdateStatus'];
export type UpdateRequest = Schemas['UpdateRequest'];
export type SecretStatus = Schemas['SecretStatus'];
export type ReloadResult = Schemas['ReloadResult'];

// The commands the app can't run for itself in Docker, where it only says what to do.
export const dockerCommands = ['docker compose pull', 'docker compose up -d'];

// displayVersion shows a release build's version with its v, as tags have it: "2.1.0" is "v2.1.0". A development
// build's version ("dev", or a git describe string) is shown as it is.
export function displayVersion(version: string, development: boolean): string {
	if (development || version.startsWith('v')) return version;
	return `v${version}`;
}

export const requestStatusLabel: Record<UpdateRequest['status'], string> = {
	pending: 'Waiting for the updater',
	running: 'Updating',
	done: 'Done',
	failed: 'Failed',
	rolled_back: 'Rolled back'
};

export function isActive(r: UpdateRequest): boolean {
	return r.status === 'pending' || r.status === 'running';
}

// activeRequest is the request still pending or running, if there is one. There's at most one.
export function activeRequest(status: UpdateStatus | null): UpdateRequest | undefined {
	return status?.requests.find(isActive);
}

// finishedOutcome says how the request that was in progress in `before` ended, once `after` shows it finished, for a
// message; null if nothing finished in between.
export function finishedOutcome(
	before: UpdateStatus | null,
	after: UpdateStatus
): { ok: boolean; message: string } | null {
	const was = activeRequest(before);
	const now = was && after.requests.find((r) => r.id === was.id);
	if (!now || isActive(now)) return null;
	switch (now.status) {
		case 'done': {
			const running = displayVersion(after.current_version, after.development);
			return { ok: true, message: `Update finished: running ${running}.` };
		}
		case 'rolled_back':
			return {
				ok: false,
				message: "The update was rolled back: the new version didn't start, and the previous one is running."
			};
		default:
			return { ok: false, message: 'The update failed before anything was changed. Its log says why.' };
	}
}

// The target version, as the server checks it: a release tag, or a prerelease tag. Empty means the latest release.
const tagPattern = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$/;

// targetProblem says what's wrong with a target version typed in, or null when it's fine.
export function targetProblem(target: string): string | null {
	const t = target.trim();
	if (t === '' || tagPattern.test(t)) return null;
	return 'A release tag such as v2.1.0 or v2.1.0-rc.1, or leave it empty for the latest release.';
}

// requestTarget names what a request updates to.
export function requestTarget(r: UpdateRequest): string {
	return r.target_version ?? 'the latest release';
}

// The update banner shows a newer release to people who can update, until they dismiss that version. A newer release
// than the one dismissed shows the banner again.
export function bannerVersion(status: UpdateStatus | null, dismissed: string | null): string | null {
	if (!status?.update_available || !status.latest) return null;
	if (status.latest.version === dismissed) return null;
	return status.latest.version;
}

export const secretKindLabel: Record<SecretStatus['kind'], string> = {
	master_key: 'Master key',
	session_key: 'Session key',
	ldap_bind_password: 'LDAP bind password',
	instance_password: 'Instance password',
	channel_secret: 'Notification channel secret'
};

// describeSource says where a secret came from, and so what a change to it needs.
export function describeSource(s: SecretStatus): string {
	if (!s.set) return 'Not set';
	switch (s.source) {
		case 'file':
			return 'From a file (Reload secrets picks up a change)';
		case 'env':
			return 'From the environment (a change needs a restart)';
		case 'generated':
			return 'Generated in the data directory';
		default:
			return 'Set';
	}
}

// describeReload sums up a reload for a message.
export function describeReload(r: ReloadResult): string {
	const parts: string[] = [];
	if (r.changed.length === 0 && r.failed.length === 0) return 'Secrets reloaded: nothing had changed.';
	if (r.changed.length > 0) parts.push(`changed: ${r.changed.join(', ')}`);
	if (r.failed.length > 0) parts.push(`failed: ${r.failed.map((f) => f.name).join(', ')}`);
	return `Secrets reloaded (${parts.join('; ')}).`;
}
