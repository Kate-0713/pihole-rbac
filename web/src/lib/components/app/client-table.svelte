<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts" module>
	import {
		columnFilteringFeature,
		createColumnHelper,
		createFilteredRowModel,
		createSortedRowModel,
		filterFn_arrIncludes,
		filterFn_includesString,
		globalFilteringFeature,
		rowSortingFeature,
		sortFn_alphanumeric,
		sortFn_basic,
		tableFeatures
	} from '@tanstack/svelte-table';
	import type { Schemas } from '#lib/api/client.js';

	type PiholeClient = Schemas['PiholeClient'];

	// As on the domains page: sorting, a filter per column and a search across columns. Here the column filter is the
	// group, kept with arrIncludes: a client shows when its groups include the one picked.
	const features = tableFeatures({
		rowSortingFeature,
		columnFilteringFeature,
		globalFilteringFeature,
		sortedRowModel: createSortedRowModel(),
		filteredRowModel: createFilteredRowModel(),
		sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
		filterFns: { includesString: filterFn_includesString, arrIncludes: filterFn_arrIncludes }
	});

	const column = createColumnHelper<typeof features, PiholeClient>();

	const columns = column.columns([
		column.accessor('client', { sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor((c) => c.name ?? '', { id: 'name', sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor('groups', { filterFn: 'arrIncludes', enableGlobalFilter: false, enableSorting: false }),
		column.accessor('comment', { sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor((c) => (c.added_at ? Date.parse(c.added_at) : 0), {
			id: 'added',
			sortFn: 'basic',
			enableGlobalFilter: false
		})
	]);
</script>

<script lang="ts">
	import ArrowDownIcon from '@lucide/svelte/icons/arrow-down';
	import ArrowUpIcon from '@lucide/svelte/icons/arrow-up';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import { createTable } from '@tanstack/svelte-table';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { groupNames, type PiholeGroup } from '#lib/pihole.js';

	let {
		clients,
		groups,
		canEdit,
		onedit
	}: {
		clients: PiholeClient[];
		groups: PiholeGroup[];
		canEdit: boolean;
		onedit: (c: PiholeClient) => void;
	} = $props();

	const table = createTable({
		features,
		columns,
		get data() {
			return clients;
		},
		initialState: { sorting: [{ id: 'client', desc: false }] }
	});

	let search = $state('');
	// A Select's value is a string, so the group's ID is kept as one, with 'all' for no filter. arrIncludes takes a list
	// of IDs, and a bare 0 (Default's ID) would read as no filter, hence [id].
	let groupFilter = $state('all');
	$effect(() => table.setGlobalFilter(search.trim()));
	$effect(() => table.getColumn('groups')?.setFilterValue(groupFilter === 'all' ? undefined : [Number(groupFilter)]));

	let rows = $derived(table.getRowModel().rows);
	// The name is the hostname Pi-hole resolved for the client, which it often doesn't have (a MAC address or subnet, or
	// no reverse DNS). The column is only shown when at least one client has one.
	let hasNames = $derived(clients.some((c) => !!c.name));
	let columnCount = $derived(4 + (hasNames ? 1 : 0) + (canEdit ? 1 : 0));
	let filtering = $derived(search.trim() !== '' || groupFilter !== 'all');
	let groupLabel = $derived(groups.find((g) => String(g.id) === groupFilter)?.name ?? 'All groups');

	const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });

	type SortableId = 'client' | 'name' | 'comment' | 'added';
	function sortState(id: SortableId): false | 'asc' | 'desc' {
		return table.getColumn(id)?.getIsSorted() ?? false;
	}
	function ariaSort(id: SortableId): 'ascending' | 'descending' | 'none' {
		const s = sortState(id);
		return s === 'asc' ? 'ascending' : s === 'desc' ? 'descending' : 'none';
	}
</script>

{#snippet sortHeader(id: SortableId, label: string)}
	<Table.Head aria-sort={ariaSort(id)}>
		<Button variant="ghost" size="sm" class="-ml-2.5" onclick={() => table.getColumn(id)?.toggleSorting()}>
			{label}
			{#if sortState(id) === 'asc'}
				<ArrowUpIcon />
			{:else if sortState(id) === 'desc'}
				<ArrowDownIcon />
			{:else}
				<ChevronsUpDownIcon class="opacity-40" />
			{/if}
		</Button>
	</Table.Head>
{/snippet}

<div class="flex flex-wrap items-end gap-2">
	<div class="grid min-w-48 flex-1 gap-1">
		<label for="client-search" class="text-muted-foreground text-xs">Search</label>
		<Input
			id="client-search"
			type="search"
			bind:value={search}
			placeholder={hasNames ? 'Address, name or comment' : 'Address or comment'}
			autocomplete="off"
		/>
	</div>
	<Select.Root type="single" bind:value={groupFilter}>
		<Select.Trigger class="w-44" aria-label="Group">{groupLabel}</Select.Trigger>
		<Select.Content>
			<Select.Item value="all" label="All groups">All groups</Select.Item>
			{#each groups as g (g.id)}
				<Select.Item value={String(g.id)} label={g.name}>{g.name}</Select.Item>
			{/each}
		</Select.Content>
	</Select.Root>
</div>

<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if filtering}Showing {rows.length} of {clients.length} clients{:else}{clients.length} clients{/if}
</p>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				{@render sortHeader('client', 'Client')}
				{#if hasNames}{@render sortHeader('name', 'Name')}{/if}
				<Table.Head>Groups</Table.Head>
				{@render sortHeader('comment', 'Comment')}
				{@render sortHeader('added', 'Added')}
				{#if canEdit}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each rows as row (row.original.client)}
				{@const c = row.original}
				<Table.Row>
					<Table.Cell><span class="font-mono text-sm break-all">{c.client}</span></Table.Cell>
					{#if hasNames}<Table.Cell class="text-sm">{c.name ?? ''}</Table.Cell>{/if}
					<Table.Cell class="text-sm">{groupNames(c.groups, groups).join(', ') || '—'}</Table.Cell>
					<Table.Cell class="text-muted-foreground max-w-64 text-sm break-words whitespace-normal">
						{c.comment}
					</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap">
						{c.added_at ? dateFormat.format(new Date(c.added_at)) : '—'}
					</Table.Cell>
					{#if canEdit}
						<Table.Cell class="text-right">
							<Button variant="ghost" size="sm" onclick={() => onedit(c)} aria-label="Change {c.client}">Change</Button>
						</Table.Cell>
					{/if}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={columnCount} class="text-muted-foreground py-6 text-center">
						{filtering ? 'Nothing matches.' : 'No clients are set up on this Pi-hole.'}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
