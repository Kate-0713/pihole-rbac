<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import CellText from '#lib/components/app/cell-text.svelte';
	import type { PiholeGroup } from '#lib/pihole.js';
	import { defaultGroupID } from '#lib/pihole-groups.js';

	// The Pi-hole groups, in Pi-hole's own order. A Pi-hole has a handful, so a plain search box is enough here, with
	// no sorting. The Default group can't be renamed or deleted, so it has no Delete; its name is fixed in the dialog.
	let {
		groups,
		canEdit,
		busy,
		onedit,
		ontoggle,
		ondelete
	}: {
		groups: PiholeGroup[];
		canEdit: boolean;
		busy: string | null; // the name of a group being switched on or off
		onedit: (g: PiholeGroup) => void;
		ontoggle: (g: PiholeGroup) => void;
		ondelete: (g: PiholeGroup) => void;
	} = $props();

	let search = $state('');
	let rows = $derived.by(() => {
		const q = search.trim().toLowerCase();
		if (!q) return groups;
		return groups.filter((g) => g.name.toLowerCase().includes(q) || g.comment.toLowerCase().includes(q));
	});
</script>

<div class="grid max-w-sm gap-1">
	<label for="pihole-group-search" class="text-muted-foreground text-xs">Search</label>
	<Input id="pihole-group-search" type="search" bind:value={search} placeholder="Name or comment" autocomplete="off" />
</div>

<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if search.trim()}Showing {rows.length} of {groups.length} groups{:else}{groups.length} groups{/if}
</p>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				<Table.Head>Name</Table.Head>
				<Table.Head>Status</Table.Head>
				<Table.Head>Comment</Table.Head>
				<Table.Head>ID</Table.Head>
				{#if canEdit}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each rows as g (g.id)}
				<Table.Row data-group={g.name}>
					<Table.Cell>
						<CellText width="lg">
							<span class="font-medium">{g.name}</span>
							{#if g.id === defaultGroupID}<Badge variant="outline" class="ml-1">Default</Badge>{/if}
						</CellText>
					</Table.Cell>
					<Table.Cell>
						<Badge variant={g.enabled ? 'secondary' : 'destructive'}>{g.enabled ? 'Enabled' : 'Disabled'}</Badge>
					</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm"><CellText>{g.comment}</CellText></Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm">{g.id}</Table.Cell>
					{#if canEdit}
						<Table.Cell class="text-right whitespace-nowrap">
							<Button variant="ghost" size="sm" onclick={() => onedit(g)} aria-label="Change {g.name}">Change</Button>
							<Button
								variant="ghost"
								size="sm"
								disabled={busy === g.name}
								onclick={() => ontoggle(g)}
								aria-label="{g.enabled ? 'Disable' : 'Enable'} {g.name}">{g.enabled ? 'Disable' : 'Enable'}</Button
							>
							{#if g.id !== defaultGroupID}
								<Button
									variant="ghost"
									size="sm"
									class="text-destructive"
									onclick={() => ondelete(g)}
									aria-label="Delete {g.name}">Delete</Button
								>
							{/if}
						</Table.Cell>
					{/if}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={canEdit ? 5 : 4} class="text-muted-foreground py-6 text-center">
						{search.trim() ? 'Nothing matches.' : 'No groups.'}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
