// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Tells the user how a Pi-hole write went, from its per-instance results (see results.ts). Every instance ok is one
// success toast; each instance that failed or was skipped is its own error, which stays until dismissed. With a
// single instance that's simply a toast or an error; with a mirrored group, a partial failure shows both.
import { ApiError } from '#lib/api/client.js';
import { failedResults, summarise, type InstanceResult } from '#lib/api/results.js';
import { notices } from '#lib/stores/notices.svelte.js';
import { writeResults, type Retry } from '#lib/stores/write-results.svelte.js';

export type WriteText = {
	// What happened, without a full stop: "Blocking turned off for 5 minutes". The instances are added after it.
	done: string;
	// What failed, for the errors: "Couldn't turn blocking off".
	failed: string;
};

// How a write through a mirrored group retries the members that failed: retry sends it again to the members it
// names, and after (if given) runs when a retry is done, so the page can read its data again.
export type RetryWith = { retry: Retry; after?: () => Promise<void> | void };

// reportResults reports the results of a write that answered 200 or 207. It returns whether every instance
// succeeded. When a write with several results (a mirrored group's) didn't work everywhere and can be retried, the
// results go to the panel above the page, member by member, with a button to retry those that failed.
export function reportResults(results: readonly InstanceResult[], text: WriteText, retry?: RetryWith): boolean {
	const s = summarise(results);
	if (retry && results.length > 1 && !s.allOk) {
		writeResults.show({ ...text, results: [...results], retry: retry.retry, after: retry.after });
		return false;
	}
	if (s.ok.length > 0) notices.success(`${text.done} on ${names(s.ok)}.`);
	for (const r of [...s.failed, ...s.skipped]) notices.error(r.error?.message ?? `Pi-hole "${r.instance}" failed.`, text.failed);
	return s.allOk;
}

// reportFailure reports a write that threw: no instance succeeded, or the request was refused before any Pi-hole was
// asked (bad input, no permission). When the error carries results, each instance's own error is shown.
export function reportFailure(e: unknown, text: WriteText, retry?: RetryWith): void {
	const results = failedResults(e);
	if (results && results.length > 0) {
		reportResults(results, text, retry);
		return;
	}
	notices.error(e, text.failed);
}

// failureMessage is what to show inside a form when a write fails, so the form can stay open for another try: each
// instance's own error when the failure carries results, otherwise the error's message.
export function failureMessage(e: unknown): string {
	const results = failedResults(e);
	if (results && results.length > 0) {
		return results.map((r) => r.error?.message ?? `Pi-hole "${r.instance}" failed.`).join(' ');
	}
	if (e instanceof ApiError) return e.message;
	return 'Something went wrong. Try again.';
}

function names(results: readonly InstanceResult[]): string {
	const list = results.map((r) => r.instance);
	return list.length <= 2 ? list.join(' and ') : `${list.slice(0, -1).join(', ')} and ${list.at(-1)}`;
}
