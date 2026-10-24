// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// whileVisible calls fn every `ms` milliseconds while the page is visible. It stops while the tab is hidden, so a
// forgotten tab doesn't keep asking the Pi-holes, and calls fn at once when the tab is shown again, so what was
// hidden is never shown stale. It returns a function that stops it all.
//
// Meant to be returned from a Svelte $effect, which calls the returned function when the component goes away:
//
//	$effect(() => whileVisible(refresh, 15_000));
export function whileVisible(fn: () => void, ms: number, doc: VisibilitySource = document): () => void {
	let timer: ReturnType<typeof setInterval> | undefined;
	const start = () => {
		stop();
		timer = setInterval(fn, ms);
	};
	const stop = () => {
		if (timer !== undefined) clearInterval(timer);
		timer = undefined;
	};
	const changed = () => {
		if (doc.hidden) {
			stop();
		} else {
			fn();
			start();
		}
	};

	if (!doc.hidden) start();
	doc.addEventListener('visibilitychange', changed);
	return () => {
		stop();
		doc.removeEventListener('visibilitychange', changed);
	};
}

// The part of `document` whileVisible needs, so tests can pass their own.
export type VisibilitySource = {
	readonly hidden: boolean;
	addEventListener(type: 'visibilitychange', listener: () => void): void;
	removeEventListener(type: 'visibilitychange', listener: () => void): void;
};
