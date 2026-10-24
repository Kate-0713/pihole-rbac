<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	// SvelteKit renders the nearest +error.svelte when a load throws error() or no route matches. This one sits in
	// the root, so it shows inside the root layout (with the source link) but without the app header.
	import { page } from '$app/state';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
</script>

<svelte:head>
	<title>{page.status === 404 ? 'Not found' : 'Error'} · pihole-rbac</title>
</svelte:head>

<main class="m-auto max-w-md p-6 text-center">
	<h1 class="text-lg font-semibold">{page.status === 404 ? "This page doesn't exist" : 'Something went wrong'}</h1>
	<p class="text-muted-foreground mt-2 text-sm">
		{page.status === 404 ? 'It may not have been built yet, or the link is wrong.' : page.error?.message}
	</p>
	<a class={buttonVariants({ class: 'mt-4' })} href="/">Go to the dashboard</a>
</main>
