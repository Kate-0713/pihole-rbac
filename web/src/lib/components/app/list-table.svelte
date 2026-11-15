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
	import type { PiholeList } from '#lib/lists.js';

	// As the domain table: sorting, a filter on the type, and a search across the address and comment.
	const features = tableFeatures({
		rowSortingFeature,
		columnFilteringFeature,
		globalFilteringFeature,
		sortedRowModel: createSortedRowModel(),
		filteredRowModel: createFilteredRowModel(),
		sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
		filterFns: { includesString: filterFn_includesString, equalsString: filterFn_equalsString }
	});

	const column = createColumnHelper<typeof features, PiholeList>();

	const columns = column.columns([
		column.accessor('address', { sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor('type', { filterFn: 'equalsString', enableGlobalFilter: false }),
		column.accessor('comment', { sortFn: 'alphanumeric', filterFn: 'includesString' }),
		column.accessor('domains', { sortFn: 'basic', enableGlobalFilter: false }),
		column.accessor((l) => (l.updated_at ? Date.parse(l.updated_at) : 0), {
			id: 'updated',
			sortFn: 'basic',
			enableGlobalFilter: false
		})
	]);
</script>

<script lang="ts">
	import ArrowDownIcon from '@lucide/svelte/icons/arrow-down';
	import ArrowUpIcon from '@lucide/svelte/icons/arrow-up';
	import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import { createTable } from '@tanstack/svelte-table';
	import { SvelteSet } from 'svelte/reactivity';
	import CellText from '#lib/components/app/cell-text.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { formatDateTime } from '#lib/format.js';
	import {
		listKey,
		markHint,
		markLabel,
		memberProblems,
		statusLabel,
		statusTone,
		typeLabel,
		type ListStatus,
		type ListType
	} from '#lib/lists.js';
	import { groupNames, type PiholeGroup } from '#lib/pihole.js';

	let {
		lists,
		groups,
		canEdit,
		busy = null,
		onedit,
		ontoggle,
		ondelete
	}: {
		lists: PiholeList[];
		groups: PiholeGroup[];
		canEdit: boolean;
		// The key of a list being enabled or disabled, whose button waits.
		busy?: string | null;
		onedit: (l: PiholeList) => void;
		ontoggle: (l: PiholeList) => void;
		ondelete: (l: PiholeList) => void;
	} = $props();

	const table = createTable({
		features,
		columns,
		get data() {
			return lists;
		},
		initialState: { sorting: [{ id: 'address', desc: false }] }
	});

	let search = $state('');
	let typeFilter = $state('all');
	$effect(() => table.setGlobalFilter(search.trim()));
	$effect(() => table.getColumn('type')?.setFilterValue(typeFilter === 'all' ? undefined : typeFilter));

	let rows = $derived(table.getRowModel().rows);
	let filtering = $derived(search.trim() !== '' || typeFilter !== 'all');
	// Through a mirrored group, each list has its members' own statuses, shown when its row is opened. SvelteSet is
	// a Set whose changes Svelte tracks, so opening a row redraws it.
	let mirrored = $derived(lists.some((l) => l.members !== undefined));
	let open = new SvelteSet<string>();
	let cols = $derived(6 + (canEdit ? 1 : 0) + (mirrored ? 1 : 0));

	const toneClass: Record<(typeof statusTone)[ListStatus], string> = {
		ok: '',
		warn: 'border-amber-500 text-amber-700 dark:text-amber-400',
		bad: '',
		none: 'text-muted-foreground'
	};

	type SortableId = 'address' | 'comment' | 'domains' | 'updated';
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

{#snippet status(s: ListStatus)}
	<Badge variant={statusTone[s] === 'bad' ? 'destructive' : 'outline'} class={toneClass[statusTone[s]]}>
		{statusLabel[s]}
	</Badge>
{/snippet}

<div class="flex flex-wrap items-end gap-2">
	<div class="grid min-w-48 flex-1 gap-1">
		<label for="list-search" class="text-muted-foreground text-xs">Search</label>
		<Input id="list-search" type="search" bind:value={search} placeholder="Address or comment" autocomplete="off" />
	</div>
	<Select.Root type="single" bind:value={typeFilter}>
		<Select.Trigger class="w-40" aria-label="Type">
			{typeFilter === 'all' ? 'Both types' : `${typeLabel[typeFilter as ListType]}s`}
		</Select.Trigger>
		<Select.Content>
			<Select.Item value="all" label="Both types">Both types</Select.Item>
			<Select.Item value="block" label="Blocklists">Blocklists</Select.Item>
			<Select.Item value="allow" label="Allowlists">Allowlists</Select.Item>
		</Select.Content>
	</Select.Root>
</div>

<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if filtering}Showing {rows.length} of {lists.length} lists{:else}{lists.length} lists{/if}
</p>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				{#if mirrored}<Table.Head class="w-0"><span class="sr-only">Members</span></Table.Head>{/if}
				{@render sortHeader('address', 'Address')}
				<Table.Head>Status</Table.Head>
				{@render sortHeader('domains', 'Domains')}
				{@render sortHeader('updated', 'Last changed')}
				<Table.Head>Groups</Table.Head>
				{@render sortHeader('comment', 'Comment')}
				{#if canEdit}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each rows as row (listKey(row.original))}
				{@const l = row.original}
				{@const key = listKey(l)}
				{@const problems = memberProblems(l)}
				<Table.Row data-list={key}>
					{#if mirrored}
						<Table.Cell>
							<Button
								variant="ghost"
								size="icon"
								aria-expanded={open.has(key)}
								aria-label="{open.has(key) ? 'Hide' : 'Show'} each member's status for {l.address}"
								onclick={() => (open.has(key) ? open.delete(key) : open.add(key))}
							>
								{#if open.has(key)}<ChevronDownIcon />{:else}<ChevronRightIcon />{/if}
							</Button>
						</Table.Cell>
					{/if}
					<Table.Cell>
						<CellText width="lg">
							<span class="font-mono text-sm">{l.address}</span>
							<span class="mt-1 flex flex-wrap gap-1">
								<Badge variant={l.type === 'block' ? 'secondary' : 'outline'}>{typeLabel[l.type]}</Badge>
								{#if !l.enabled}<Badge variant="outline">Disabled</Badge>{/if}
								{#if l.needs_gravity}<Badge variant="outline">Waiting for gravity</Badge>{/if}
								{#each l.marks as m (m)}
									<Badge variant="outline" title={markHint[m]}>{markLabel[m]}</Badge>
								{/each}
							</span>
						</CellText>
					</Table.Cell>
					<Table.Cell class="whitespace-normal">
						<div class="flex flex-wrap items-center gap-1">
							{@render status(l.status)}
							{#if l.invalid_domains > 0}
								<span class="text-muted-foreground text-xs">{l.invalid_domains.toLocaleString()} invalid lines</span>
							{/if}
						</div>
						{#if problems.length > 0}
							<p class="mt-1 flex items-start gap-1 text-xs text-amber-700 dark:text-amber-400">
								<TriangleAlertIcon class="size-3.5 shrink-0" />
								<span>{problems.join('; ')}</span>
							</p>
						{/if}
					</Table.Cell>
					<Table.Cell class="text-sm tabular-nums">{l.domains.toLocaleString()}</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap">
						{l.updated_at ? formatDateTime(l.updated_at) : '—'}
					</Table.Cell>
					<Table.Cell class="text-sm"><CellText>{groupNames(l.groups, groups).join(', ') || '—'}</CellText></Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm"><CellText>{l.comment}</CellText></Table.Cell>
					{#if canEdit}
						<Table.Cell class="text-right whitespace-nowrap">
							<Button variant="ghost" size="sm" onclick={() => onedit(l)} aria-label="Change {l.address}">Change</Button>
							<Button
								variant="ghost"
								size="sm"
								disabled={busy === key}
								onclick={() => ontoggle(l)}
								aria-label="{l.enabled ? 'Disable' : 'Enable'} {l.address}">{l.enabled ? 'Disable' : 'Enable'}</Button
							>
							<Button
								variant="ghost"
								size="sm"
								class="text-destructive"
								onclick={() => ondelete(l)}
								aria-label="Delete {l.address}">Delete</Button
							>
						</Table.Cell>
					{/if}
				</Table.Row>
				{#if mirrored && open.has(key)}
					<Table.Row class="bg-muted/40 hover:bg-muted/40">
						<Table.Cell colspan={cols}>
							<ul class="grid gap-1 text-sm" aria-label="Each member's status for {l.address}">
								{#each l.members ?? [] as m (m.instance_id)}
									<li class="flex flex-wrap items-center gap-2">
										<span class="font-medium">{m.instance}</span>
										{#if m.primary}<Badge variant="outline">Primary</Badge>{/if}
										{#if m.state === 'ok' && m.status}
											{@render status(m.status)}
											<span class="text-muted-foreground text-xs">
												{(m.domains ?? 0).toLocaleString()} domains{m.updated_at ? `, changed ${formatDateTime(m.updated_at)}` : ''}
											</span>
											{#if m.needs_gravity}<Badge variant="outline">Waiting for gravity</Badge>{/if}
										{:else if m.state === 'missing'}
											<span class="text-muted-foreground text-xs">Not subscribed: see Drift.</span>
										{:else}
											<span class="text-destructive text-xs">Couldn't be read.</span>
										{/if}
									</li>
								{/each}
							</ul>
						</Table.Cell>
					</Table.Row>
				{/if}
			{:else}
				<Table.Row>
					<Table.Cell colspan={cols} class="text-muted-foreground py-6 text-center">
						{filtering ? 'Nothing matches.' : 'No lists yet.'}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
