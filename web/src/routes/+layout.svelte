<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	// Importing a CSS file in the root layout is the SvelteKit way to load global styles: Vite bundles it into the
	// build, and every page sits inside this layout.
	import '../app.css';
	import favicon from '#lib/assets/favicon.svg';
	import { Button } from '#lib/components/ui/button/index.js';
	import type { LayoutProps } from './$types';

	// Svelte 5 runes: $props() is how a component receives its props. `data` is whatever +layout.ts's load returned (typed via the generated LayoutProps); `children` is the page being rendered inside this layout.
	let { data, children }: LayoutProps = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="flex min-h-svh flex-col">
	<div class="flex flex-1 flex-col">
		{#if data.unavailable}
			<main class="m-auto max-w-md p-6 text-center">
				<h1 class="text-lg font-semibold">The server can't be reached</h1>
				<p class="text-muted-foreground mt-2 text-sm">
					pihole-rbac's API didn't answer. Check that the service is running, then try again.
				</p>
				<!-- A full reload, so the root layout's load asks the server again. -->
				<Button class="mt-4" onclick={() => window.location.reload()}>Try again</Button>
			</main>
		{:else}
			{@render children()}
		{/if}
	</div>

	<!-- AGPL-3.0 section 13: every page, including login and setup, offers the source of the running build. Lives in the root layout so no page can forget it. -->
	<footer class="text-muted-foreground border-t px-4 py-3 text-center text-xs">
		<a class="underline-offset-4 hover:underline" href={data.about.source_url} rel="noopener noreferrer">Source code</a>
		· {data.about.license}
	</footer>
</div>
