<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	// Importing a CSS file in the root layout is the SvelteKit way to load global styles: Vite bundles it into the
	// build, and every page sits inside this layout.
	import '../app.css';
	import { beforeNavigate } from '$app/navigation';
	import { updated } from '$app/state';
	import favicon from '#lib/assets/favicon.svg';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Toaster } from '#lib/components/ui/sonner/index.js';
	import { whileVisible } from '#lib/poll.js';
	import { applyTheme, theme } from '#lib/stores/theme.svelte.js';
	import type { LayoutProps } from './$types';

	// Svelte 5 runes: $props() is how a component receives its props. `data` is whatever +layout.ts's load returned (typed via the generated LayoutProps); `children` is the page being rendered inside this layout.
	let { data, children }: LayoutProps = $props();

	// Light or dark mode on every page, the login page included. The first effect follows the operating system's
	// setting (and stops following it when the layout goes away); the second puts the result on <html> each time it
	// changes. app.html has already applied it once, before the page was drawn.
	$effect(() => theme.start());
	$effect(() => applyTheme(theme.resolved));

	// A tab left open across an update keeps running the old build: an SPA moves between pages without asking the
	// server for the page again. SvelteKit stamps each build with a version and serves it at /_app/version.json;
	// updated.check() compares that with the version this tab loaded and sets updated.current when they differ. It is
	// asked every five minutes while the tab is visible, and at once when the tab is shown again (whileVisible), which
	// catches the usual case of coming back to a tab after updating. A failed ask just reports no change.
	$effect(() => whileVisible(() => void updated.check(), 5 * 60_000));
	// Once a new build is known, the next move to another page is a full page load, which brings in the new build.
	// (The SvelteKit docs' recommended pattern: setting location.href replaces the client-side navigation.)
	beforeNavigate(({ willUnload, to }) => {
		if (updated.current && !willUnload && to?.url) location.href = to.url.href;
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<!-- Success toasts, from notices.success(). Failures go to the error banner in the app layout instead. -->
<Toaster position="bottom-right" richColors closeButton theme={theme.resolved} />

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
		· {data.about.license} ·
		<!-- A file served beside the SPA, not a route: data-sveltekit-reload makes the browser load it instead of the client router. Release builds include it; a dev build answers with the app's not-found page. -->
		<a class="underline-offset-4 hover:underline" href="/THIRD_PARTY_NOTICES.txt" data-sveltekit-reload>Third-party notices</a>
	</footer>
</div>
