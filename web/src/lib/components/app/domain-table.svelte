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
		filterFn_equalsString,
		filterFn_includesString,
		globalFilteringFeature,
		rowSortingFeature,
		sortFn_alphanumeric,
		sortFn_basic,
		tableFeatures
	} from '@tanstack/svelte-table';
	import type { Domain } from '#lib/domains.js';

	// TanStack Table v9 is built from features, declared once, outside the component, as its docs recommend: sorting,
	// a filter per column (list and match) and a search across columns. The sort and filter functions named here are
	// the only ones the columns may use, which TypeScript checks.
	const features = tableFeatures({
		rowSortingFeature,
		columnFilteringFeature,
		globalFilteringFeature,
		sortedRowModel: createSortedRowModel(),
		filteredRowModel: createFilteredRowModel(),
		sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
		filterFns: { includesString: filterFn_includesString, equalsString: filterFn_equalsString }
	});

	const column = createColumnHelper<typeof features, Domain>();

	// Columns as TanStack sees them: what to sort and filter on. How each cell looks is in the markup below.
	// column.columns keeps each column's own value type (a string here, a number there) rather than widening them.
	const columns = column.columns([
		column.accessor('domain', { sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor('type', { filterFn: 'equalsString', enableGlobalFilter: false }),
		column.accessor('kind', { filterFn: 'equalsString', enableGlobalFilter: false }),
		column.accessor('comment', { sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor((d) => (d.added_at ? Date.parse(d.added_at) : 0), {
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
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { entryKey, groupNames, kindLabel, typeLabel, type PiholeGroup } from '#lib/domains.js';

	let {
		domains,
		groups,
		canEdit,
		onedit,
		ondelete
	}: {
		domains: Domain[];
		groups: PiholeGroup[];
		canEdit: boolean;
		onedit: (d: Domain) => void;
		ondelete: (d: Domain) => void;
	} = $props();

	// createTable keeps the sorting and filters, and gives rows already sorted and filtered. Passing data as a getter
	// lets the table see new domains whenever the page's load runs again.
	const table = createTable({
		features,
		columns,
		get data() {
			return domains;
		},
		initialState: { sorting: [{ id: 'domain', desc: false }] }
	});

	// The filter controls. Their values live here, as $state, and are handed to the table when they change.
	let search = $state('');
	let listFilter = $state('all');
	let kindFilter = $state('all');
	$effect(() => table.setGlobalFilter(search.trim()));
	$effect(() => table.getColumn('type')?.setFilterValue(listFilter === 'all' ? undefined : listFilter));
	$effect(() => table.getColumn('kind')?.setFilterValue(kindFilter === 'all' ? undefined : kindFilter));

	let rows = $derived(table.getRowModel().rows);
	let filtering = $derived(search.trim() !== '' || listFilter !== 'all' || kindFilter !== 'all');

	const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });

	// A header that sorts its column. aria-sort tells screen readers which way the table is sorted.
	type SortableId = 'domain' | 'comment' | 'added';
	function sortState(id: SortableId): false | 'asc' | 'desc' {
		return table.getColumn(id)?.getIsSorted() ?? false;
	}
	function ariaSort(id: SortableId): 'ascending' | 'descending' | 'none' {
		const s = sortState(id);
		return s === 'asc' ? 'ascending' : s === 'desc' ? 'descending' : 'none';
	}
	function toggleSort(id: SortableId) {
		table.getColumn(id)?.toggleSorting();
	}
</script>

{#snippet sortHeader(id: SortableId, label: string)}
	<Table.Head aria-sort={ariaSort(id)}>
		<Button variant="ghost" size="sm" class="-ml-2.5" onclick={() => toggleSort(id)}>
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
		<label for="domain-search" class="text-muted-foreground text-xs">Search</label>
		<Input id="domain-search" type="search" bind:value={search} placeholder="Domain or comment" autocomplete="off" />
	</div>
	<Select.Root type="single" bind:value={listFilter}>
		<Select.Trigger class="w-36" aria-label="List">
			{listFilter === 'all' ? 'Both lists' : `${typeLabel[listFilter as Domain['type']]} list`}
		</Select.Trigger>
		<Select.Content>
			<Select.Item value="all" label="Both lists">Both lists</Select.Item>
			<Select.Item value="allow" label="Allow list">Allow list</Select.Item>
			<Select.Item value="deny" label="Deny list">Deny list</Select.Item>
		</Select.Content>
	</Select.Root>
	<Select.Root type="single" bind:value={kindFilter}>
		<Select.Trigger class="w-36" aria-label="Match">
			{kindFilter === 'all' ? 'Exact and regex' : kindLabel[kindFilter as Domain['kind']]}
		</Select.Trigger>
		<Select.Content>
			<Select.Item value="all" label="Exact and regex">Exact and regex</Select.Item>
			<Select.Item value="exact" label="Exact">Exact</Select.Item>
			<Select.Item value="regex" label="Regex">Regex</Select.Item>
		</Select.Content>
	</Select.Root>
</div>

<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if filtering}Showing {rows.length} of {domains.length} entries{:else}{domains.length} entries{/if}
</p>

<!-- Wide tables scroll sideways inside their own box, so the page itself never does on a phone. -->
<div class="overflow-x-auto rounded-lg border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				{@render sortHeader('domain', 'Domain')}
				<Table.Head>List</Table.Head>
				<Table.Head>Groups</Table.Head>
				{@render sortHeader('comment', 'Comment')}
				{@render sortHeader('added', 'Added')}
				{#if canEdit}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each rows as row (entryKey(row.original))}
				{@const d = row.original}
				<Table.Row data-entry={entryKey(d)}>
					<Table.Cell class="max-w-80">
						<span class="font-mono text-sm break-all">{d.domain}</span>
						{#if !d.enabled}<Badge variant="outline" class="ml-1">Disabled</Badge>{/if}
					</Table.Cell>
					<Table.Cell>
						<div class="flex gap-1">
							<Badge variant={d.type === 'deny' ? 'destructive' : 'secondary'}>{typeLabel[d.type]}</Badge>
							{#if d.kind === 'regex'}<Badge variant="outline">Regex</Badge>{/if}
						</div>
					</Table.Cell>
					<Table.Cell class="text-sm">{groupNames(d.groups, groups).join(', ') || '—'}</Table.Cell>
					<Table.Cell class="text-muted-foreground max-w-64 text-sm break-words whitespace-normal">
						{d.comment}
					</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap">
						{d.added_at ? dateFormat.format(new Date(d.added_at)) : '—'}
					</Table.Cell>
					{#if canEdit}
						<Table.Cell class="text-right whitespace-nowrap">
							<Button variant="ghost" size="sm" onclick={() => onedit(d)} aria-label="Change {d.domain}">Change</Button>
							<Button
								variant="ghost"
								size="sm"
								class="text-destructive"
								onclick={() => ondelete(d)}
								aria-label="Delete {d.domain}">Delete</Button
							>
						</Table.Cell>
					{/if}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={canEdit ? 6 : 5} class="text-muted-foreground py-6 text-center">
						{filtering ? 'Nothing matches.' : 'No entries on either list yet.'}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
