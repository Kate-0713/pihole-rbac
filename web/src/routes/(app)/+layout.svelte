<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import AppHeader from '#lib/components/app/app-header.svelte';
	import ErrorBanner from '#lib/components/app/error-banner.svelte';
	import type { LayoutProps } from './$types';

	// data.target comes from this layout's load (+layout.ts) and is the selected target's ID, or null.
	let { data, children }: LayoutProps = $props();
</script>

<AppHeader target={data.target} />

<main class="mx-auto grid w-full max-w-6xl flex-1 content-start gap-4 p-4">
	<ErrorBanner />
	{@render children()}
</main>
