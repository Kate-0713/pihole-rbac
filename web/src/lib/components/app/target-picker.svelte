<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import * as Select from '#lib/components/ui/select/index.js';
	import { can } from '#lib/permissions.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import HealthDot from './health-dot.svelte';

	let { current }: { current: string | null } = $props();

	let selected = $derived(targets.find(current));

	// Choosing a target stays on the same page and only changes ?target=, which reruns the page's load functions.
	// reset: false keeps the scroll position and focus where they were (SvelteKit 3's replacement for keepFocus and
	// noScroll). page.url is read-only, so the new URL is built from a copy.
	function choose(id: string) {
		if (id === current) return;
		const url = new URL(page.url.href);
		url.searchParams.set('target', id);
		void goto(url.pathname + url.search, { reset: false });
	}

	// The health beside each name changes over time, so the list is fetched again whenever the picker opens.
	function opened(open: boolean) {
		if (open) targets.refresh().catch((e: unknown) => notices.error(e, "Couldn't refresh your instances"));
	}
</script>

{#if targets.list.length === 0}
	<span class="text-muted-foreground text-sm">
		{#if can('instances.manage')}
			No instances yet. <a class="underline underline-offset-4" href="/admin/instances">Add one</a>
		{:else}
			No instances available
		{/if}
	</span>
{:else}
	<!-- bits-ui's Select: `value` is the selected item's value; onValueChange fires when the user picks another. -->
	<Select.Root type="single" value={current ?? undefined} onValueChange={choose} onOpenChange={opened}>
		<Select.Trigger class="w-56" aria-label="Instance">
			{#if selected}
				<span class="flex items-center gap-2 truncate">
					<HealthDot health={selected.health} />
					<span class="truncate">{selected.name}</span>
				</span>
			{:else}
				Choose an instance
			{/if}
		</Select.Trigger>
		<Select.Content>
			{#each targets.list as t (t.id)}
				<Select.Item value={t.id} label={t.name}>
					<HealthDot health={t.health} />
					<span class="truncate">{t.name}</span>
				</Select.Item>
			{/each}
		</Select.Content>
	</Select.Root>
{/if}
