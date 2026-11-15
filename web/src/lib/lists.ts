// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Helpers for the Lists page: subscribed lists (adlists) and gravity runs. addressProblem is a browser-side copy of
// the server's rules for a new list's address (CheckAddress in internal/lists), so the form can say what's wrong
// before it is sent; the server checks again.
import type { Schemas } from '#lib/api/client.js';

export type PiholeList = Schemas['PiholeList'];
export type ListType = Schemas['PiholeListType'];
export type ListStatus = Schemas['PiholeListStatus'];
export type ListMemberStatus = Schemas['PiholeListMemberStatus'];
export type GravityRun = Schemas['GravityRun'];
export type GravityResult = Schemas['GravityInstanceResult'];
export type GravityLine = Schemas['GravityLine'];

export const maxAddressBytes = 2048;

export const typeLabel: Record<ListType, string> = { block: 'Blocklist', allow: 'Allowlist' };

// How each download status is shown: the label, and how worrying it is.
export const statusLabel: Record<ListStatus, string> = {
	never: 'Not downloaded yet',
	updated: 'Updated',
	unchanged: 'Unchanged',
	cached: 'Download failed (old copy used)',
	failed: 'Download failed'
};
export const statusTone: Record<ListStatus, 'ok' | 'warn' | 'bad' | 'none'> = {
	never: 'none',
	updated: 'ok',
	unchanged: 'ok',
	cached: 'warn',
	failed: 'bad'
};

export const markLabel: Record<PiholeList['marks'][number], string> = {
	file: 'file: list',
	scheme: 'Other scheme',
	credentials: 'Login in address'
};
export const markHint: Record<PiholeList['marks'][number], string> = {
	file: 'Pi-hole reads this file on its own host. New file: lists need allow_file_lists in the settings.',
	scheme: "New lists can only be http or https. This one can still be changed and deleted.",
	credentials: 'The address has a user name or password in it, hidden here. New lists can\'t have one.'
};

const bytes = (s: string) => new TextEncoder().encode(s).length;
// Any whitespace or control character, as the server's unicode.IsSpace / IsControl check refuses.
const spaceOrControl = /[\s\p{Cc}]/u;

// addressProblem returns what's wrong with a new list's address as typed, or null. Surrounding spaces are ignored,
// as the server ignores them. allowFile is the allow_file_lists setting, when the page knows it; the server decides.
export function addressProblem(address: string, allowFile = false): string | null {
	const a = address.trim();
	if (a === '') return 'Enter the list\'s address.';
	if (bytes(a) > maxAddressBytes) return `An address can be at most ${maxAddressBytes} bytes.`;
	if (spaceOrControl.test(a)) return "It can't contain spaces or control characters.";
	const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(a);
	if (authority?.[1].includes('@')) {
		return "Leave the user name and password out: the address is shown to everyone who can see the lists.";
	}
	const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(a)?.[1].toLowerCase();
	if (scheme === 'http' || scheme === 'https') {
		// The browser's URL parser is more forgiving than the server's (https:///x has a host to it), so the part
		// after :// must name a host itself.
		if (!authority || authority[1] === '' || authority[1].startsWith(':')) return 'The address needs a host.';
		let host = '';
		try {
			host = new URL(a).hostname;
		} catch {
			return "That isn't a valid address.";
		}
		return host === '' ? 'The address needs a host.' : null;
	}
	if (scheme === 'file') {
		if (!allowFile) return 'file: lists are turned off. An administrator can allow them in the settings.';
		return /^file:(\/\/(localhost)?)?\//i.test(a) ? null : 'A file: address needs an absolute path, like file:///etc/pihole/list.txt.';
	}
	if (scheme === undefined) return 'Start the address with https:// or http://.';
	return `${scheme}: addresses aren't allowed, only http and https.`;
}

// listKey identifies a list, for keyed {#each} blocks and test IDs: the same address can be on both types.
export function listKey(l: Pick<PiholeList, 'address' | 'type'>): string {
	return `${l.type}/${l.address}`;
}

// memberProblems lists the members of a mirrored group whose copy of a list needs a look: a failed download, or the
// list missing there. Empty for an instance's list.
export function memberProblems(l: PiholeList): string[] {
	const out: string[] = [];
	for (const m of l.members ?? []) {
		if (m.state === 'missing') out.push(`${m.instance}: not subscribed`);
		else if (m.state === 'unreadable') out.push(`${m.instance}: couldn't be read`);
		else if (m.status === 'cached' || m.status === 'failed') out.push(`${m.instance}: ${statusLabel[m.status].toLowerCase()}`);
	}
	return out;
}

// waitingCount is how many lists wait for a gravity run.
export function waitingCount(lists: readonly PiholeList[]): number {
	return lists.filter((l) => l.needs_gravity).length;
}

export const resultLabel: Record<GravityResult['status'], string> = {
	pending: 'Waiting',
	running: 'Running',
	ok: 'Done',
	failed: 'Failed',
	skipped: 'Skipped'
};

// resultText says how one instance's part of a run went, in a sentence.
export function resultText(r: GravityResult): string {
	switch (r.status) {
		case 'pending':
			return 'Waiting for its turn.';
		case 'running':
			return 'Running gravity…';
		case 'ok': {
			const parts = [`${(r.domains ?? 0).toLocaleString()} domains`];
			if (r.duration_ms !== undefined) parts.push(`in ${formatDuration(r.duration_ms)}`);
			let s = `Done: ${parts.join(' ')}.`;
			if (r.lists_failed) s += ` ${r.lists_failed === 1 ? '1 list' : `${r.lists_failed} lists`} failed to download.`;
			return s;
		}
		case 'failed':
			return r.error?.message ?? 'Failed.';
		case 'skipped':
			return r.reason === 'down'
				? `Skipped: it couldn't be reached.${r.error ? ` ${r.error.message}` : ''}`
				: 'Skipped, since an earlier member failed.';
	}
}

export function formatDuration(ms: number): string {
	if (ms < 1000) return 'under a second';
	const s = Math.round(ms / 1000);
	if (s < 60) return `${s}s`;
	return `${Math.floor(s / 60)}m ${s % 60}s`;
}

// runSummary says how a finished run went, for the toast.
export function runSummary(run: GravityRun): { ok: boolean; text: string } {
	const failed = run.results.filter((r) => r.status === 'failed');
	const skipped = run.results.filter((r) => r.status === 'skipped');
	const done = run.results.filter((r) => r.status === 'ok');
	if (failed.length === 0 && skipped.length === 0) {
		return { ok: true, text: `Gravity updated on ${names(done.map((r) => r.instance))}.` };
	}
	const parts: string[] = [];
	if (done.length > 0) parts.push(`updated on ${names(done.map((r) => r.instance))}`);
	if (failed.length > 0) parts.push(`failed on ${names(failed.map((r) => r.instance))}`);
	if (skipped.length > 0) parts.push(`skipped on ${names(skipped.map((r) => r.instance))}`);
	const text = parts.join('; ');
	return { ok: false, text: `Gravity ${text}.` };
}

function names(list: string[]): string {
	return list.length <= 2 ? list.join(' and ') : `${list.slice(0, -1).join(', ')} and ${list.at(-1)}`;
}

// The most lines the panel keeps on screen. The server keeps more; this only bounds the page.
export const maxShownLines = 2000;

// mergeOutput adds newly read lines to those already shown, in order and without repeats, keeping the newest
// maxShownLines. A read that skipped lines (truncated) is marked with a gap line, seq 0.
export function mergeOutput(shown: readonly GravityLine[], run: Pick<GravityRun, 'output' | 'output_truncated'>): GravityLine[] {
	const last = shown.at(-1)?.seq ?? 0;
	const fresh = run.output.filter((l) => l.seq > last);
	const out = [...shown];
	if (run.output_truncated && fresh.length > 0 && shown.length > 0) {
		out.push({ seq: 0, instance_id: 0, text: '… (some lines were left out)' });
	}
	out.push(...fresh);
	return out.length > maxShownLines ? out.slice(out.length - maxShownLines) : out;
}
