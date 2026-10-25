// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The per-member results of a write through a mirrored group that didn't work everywhere, shown in a panel above the
// page with a button to retry the members that failed. The retry sends the same request with ?members= naming them,
// so the members that worked aren't asked again. One panel at a time: a newer write's results replace it.
import { failedResults, summarise, type InstanceResult } from '#lib/api/results.js';
import { notices } from './notices.svelte.js';

// Sends the write again to the members named (instance IDs) and returns their results.
export type Retry = (members: number[]) => Promise<readonly InstanceResult[]>;

export type ResultsPanel = {
	// The write's words, as for reportResults: "games.example added to the deny list", "Couldn't add games.example".
	done: string;
	failed: string;
	results: InstanceResult[];
	retry: Retry;
	// Called after a retry, whatever its result, so the page can read its data again.
	after?: () => Promise<void> | void;
};

// mergeResults puts a retry's results in place of the earlier ones for the members it covered, keeping the order.
export function mergeResults(before: readonly InstanceResult[], retried: readonly InstanceResult[]): InstanceResult[] {
	return before.map((r) => retried.find((x) => x.instance_id === r.instance_id) ?? r);
}

// toRetry is the members a retry should name: those that failed or weren't reached.
export function toRetry(results: readonly InstanceResult[]): number[] {
	return results.filter((r) => r.status !== 'ok').map((r) => r.instance_id);
}

class WriteResultsStore {
	panel = $state<ResultsPanel | null>(null);
	busy = $state(false);

	show(panel: ResultsPanel): void {
		this.panel = panel;
	}

	dismiss(): void {
		this.panel = null;
	}

	async retry(): Promise<void> {
		const p = this.panel;
		if (!p || this.busy) return;
		this.busy = true;
		let merged = p.results;
		try {
			merged = mergeResults(p.results, await p.retry(toRetry(p.results)));
		} catch (e) {
			// None of the retried members worked; their new errors, when the failure carries them, replace the old.
			const results = failedResults(e);
			if (results && results.length > 0) merged = mergeResults(p.results, results);
			else notices.error(e, p.failed);
		} finally {
			this.busy = false;
		}
		// Only if the panel still shows this write: a newer one may have replaced it meanwhile.
		if (this.panel === p) {
			if (summarise(merged).allOk) {
				notices.success(`${p.done} on every member.`);
				this.panel = null;
			} else {
				this.panel = { ...p, results: merged };
			}
		}
		await p.after?.();
	}
}

export const writeResults = new WriteResultsStore();
