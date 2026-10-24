<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import HealthDot from '#lib/components/app/health-dot.svelte';
	import { session } from '#lib/stores/session.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import type { PageProps } from './$types';

	// `data` includes what every layout above returned, so data.target is the (app) layout's selected target.
	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Dashboard · pihole-rbac</title>
</svelte:head>

<!-- Placeholder until the dashboard itself is built. -->
<h1 class="text-xl font-semibold">Dashboard</h1>
{#if target}
	<p class="flex items-center gap-2 text-sm">
		<HealthDot health={target.health} />
		{target.name}
		<span class="text-muted-foreground">· {target.health?.state ?? 'unknown'}</span>
	</p>
	<p class="text-muted-foreground text-sm">Blocking status and statistics for this instance will appear here.</p>
{:else}
	<p class="text-muted-foreground text-sm">
		Welcome, {session.user?.username}. You don't have access to any instance yet.
	</p>
{/if}
