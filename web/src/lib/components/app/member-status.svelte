<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import type { Schemas } from '#lib/api/client.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import type { Target } from '#lib/stores/targets.svelte.js';
	import HealthDot from './health-dot.svelte';

	type MemberRead = Schemas['MemberRead'];
	type Blocking = Schemas['BlockingStatus']['blocking'];

	// A mirrored group's members on the dashboard: each one's health, and what it said in the summary just read (its
	// blocking state, or why it didn't answer). A member missing from the summary is shown with its health alone.
	let { members, reads }: { members: NonNullable<Target['members']>; reads: MemberRead[] | undefined } = $props();

	const blockingLabel: Record<Blocking, string> = {
		enabled: 'Blocking on',
		disabled: 'Blocking off',
		mixed: 'Mixed',
		failed: "Couldn't tell",
		unknown: "Couldn't tell"
	};

	let byID = $derived(new Map((reads ?? []).map((r) => [r.instance_id, r])));
</script>

<ul class="grid gap-2" aria-label="Members">
	{#each members as m (m.instance_id)}
		{@const read = byID.get(m.instance_id)}
		<li class="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
			<HealthDot health={m.health} />
			<span class="font-medium">{m.name}</span>
			{#if m.primary}<Badge variant="outline">Primary</Badge>{/if}
			{#if read?.status === 'ok' && read.blocking}
				<span class="text-muted-foreground">· {blockingLabel[read.blocking.blocking]}</span>
			{:else if read?.error}
				<span class="text-destructive">· {read.error.message}</span>
			{/if}
		</li>
	{/each}
</ul>
