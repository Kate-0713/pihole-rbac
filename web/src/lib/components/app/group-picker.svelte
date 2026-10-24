<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import type { PiholeGroup } from '#lib/pihole.js';

	// $bindable lets the parent write bind:selected={ids}, so ticking a box updates the parent's array, the Svelte 5
	// way of a two-way prop.
	let {
		groups,
		selected = $bindable([]),
		disabled = false,
		idPrefix
	}: { groups: PiholeGroup[]; selected: number[]; disabled?: boolean; idPrefix: string } = $props();

	function toggle(id: number, on: boolean) {
		selected = on ? [...selected, id].sort((a, b) => a - b) : selected.filter((g) => g !== id);
	}
</script>

<fieldset class="grid gap-2" {disabled}>
	<legend class="mb-1 text-sm font-medium">Groups</legend>
	{#if groups.length === 0}
		<p class="text-muted-foreground text-sm">This Pi-hole has no groups.</p>
	{/if}
	<div class="grid max-h-48 gap-2 overflow-y-auto sm:grid-cols-2">
		{#each groups as g (g.id)}
			<div class="flex items-center gap-2">
				<Checkbox
					id="{idPrefix}-group-{g.id}"
					checked={selected.includes(g.id)}
					onCheckedChange={(on) => toggle(g.id, on === true)}
					{disabled}
				/>
				<Label for="{idPrefix}-group-{g.id}" class="font-normal">
					{g.name}
					{#if !g.enabled}<span class="text-muted-foreground text-xs">(disabled)</span>{/if}
				</Label>
			</div>
		{/each}
	</div>
	{#if selected.length === 0 && groups.length > 0}
		<p class="text-muted-foreground text-xs">In no group, the entry applies to no client.</p>
	{/if}
</fieldset>
