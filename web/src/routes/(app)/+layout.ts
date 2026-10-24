// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { redirect } from '@sveltejs/kit';
import { notices } from '#lib/stores/notices.svelte.js';
import { loginURL, session } from '#lib/stores/session.svelte.js';
import { targets, usesTarget } from '#lib/stores/targets.svelte.js';
import type { LayoutLoad } from './$types';

// SvelteKit convention: a folder in (parentheses) is a route group. It adds a layout to the pages inside it without
// adding anything to their URLs, so (app)/dashboard/+page.svelte is "/dashboard". Every page that needs a session
// lives here.
//
// This only decides what to render. The server refuses every API request without a session whatever the UI does.
export const load: LayoutLoad = async ({ parent, url, fetch }) => {
	await parent(); // the root layout's load has asked the server about the session by now
	if (session.status !== 'authenticated') redirect(307, loginURL(url.pathname + url.search));

	try {
		await targets.load(fetch);
	} catch (e) {
		// The pages still work without the list (admin pages don't need it); say why the picker is empty.
		notices.error(e, "Couldn't load your instances");
	}

	// Admin pages don't act on a target, so their URLs stay clean: any ?target= is dropped. The nav links on them still
	// lead back to the instance used last.
	if (!usesTarget(url.pathname)) {
		if (url.searchParams.has('target')) {
			const next = new URL(url);
			next.searchParams.delete('target');
			redirect(307, next.pathname + next.search);
		}
		return { target: targets.fallback()?.id ?? null };
	}

	// Every other page carries the selected target in its URL, so a link always opens the same instance. When the URL
	// names none, or one this user can't act on, use the remembered or first one instead.
	const asked = url.searchParams.get('target');
	const chosen = targets.find(asked) ?? targets.fallback();
	if (chosen?.id !== (asked ?? undefined)) {
		if (asked && targets.loaded) {
			// Deliberately vague: the list only holds what this user may see, so it can't tell "doesn't exist" from
			// "not yours", and neither should the message.
			notices.info(
				chosen
					? `That instance isn't available to you. Showing ${chosen.name} instead.`
					: "That instance isn't available to you."
			);
		}
		const next = new URL(url);
		if (chosen) next.searchParams.set('target', chosen.id);
		else next.searchParams.delete('target');
		redirect(307, next.pathname + next.search);
	}
	if (chosen) targets.remember(chosen.id);

	// Pages get the target's ID, not the object, and look it up in the store, so health updates reach them.
	return { target: chosen?.id ?? null };
};
