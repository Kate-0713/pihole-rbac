<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import AppHeader from '#lib/components/app/app-header.svelte';
	import ErrorBanner from '#lib/components/app/error-banner.svelte';
	import WriteResultsPanel from '#lib/components/app/write-results-panel.svelte';
	import { writeResults } from '#lib/stores/write-results.svelte.js';
	import type { LayoutProps } from './$types';

	// data.target comes from this layout's load (+layout.ts) and is the selected target's ID, or null.
	let { data, children }: LayoutProps = $props();

	// A write's per-member results belong to the target they were made on: picking another one puts them away.
	// The effect reads data.target, so it runs again each time the target changes.
	$effect(() => {
		void data.target;
		writeResults.dismiss();
	});
</script>

<AppHeader target={data.target} />

<main class="mx-auto grid w-full max-w-6xl flex-1 content-start gap-4 p-4">
	<ErrorBanner />
	<WriteResultsPanel />
	{@render children()}
</main>
