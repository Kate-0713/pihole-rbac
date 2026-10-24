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
		rowSortingFeature,
		sortFn_alphanumeric,
		sortFn_basic,
		tableFeatures
	} from '@tanstack/svelte-table';
	import { describeStatus, type QueryLogEntry } from '#lib/queries.js';

	// The domain and client filters run on the server (they decide what is read); sorting, and the blocked or
	// allowed filter, run here on what came back.
	const features = tableFeatures({
		rowSortingFeature,
		columnFilteringFeature,
		sortedRowModel: createSortedRowModel(),
		filteredRowModel: createFilteredRowModel(),
		sortFns: { alphanumeric: sortFn_alphanumeric, basic: sortFn_basic },
		filterFns: { equalsString: filterFn_equalsString }
	});

	const column = createColumnHelper<typeof features, QueryLogEntry>();

	const columns = column.columns([
		column.accessor((q) => Date.parse(q.time), { id: 'time', sortFn: 'basic' }),
		column.accessor('domain', { sortFn: 'alphanumeric' }),
		column.accessor((q) => q.client_name ?? q.client_ip, { id: 'client', sortFn: 'alphanumeric' }),
		column.accessor((q) => describeStatus(q.status).label, { id: 'status', sortFn: 'alphanumeric' }),
		column.accessor((q) => describeStatus(q.status).kind, { id: 'kind', filterFn: 'equalsString' }),
		column.accessor((q) => q.reply_time_ms ?? -1, { id: 'reply', sortFn: 'basic' })
	]);
</script>

<script lang="ts">
	import ArrowDownIcon from '@lucide/svelte/icons/arrow-down';
	import ArrowUpIcon from '@lucide/svelte/icons/arrow-up';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import { createTable } from '@tanstack/svelte-table';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { formatReplyTime } from '#lib/queries.js';

	// filterHref gives the link that filters the log by a domain or client, so a value in the table can be clicked
	// to narrow the log to it.
	// empty is what to say when nothing came back at all, which depends on the server-side filters.
	let {
		queries,
		filterHref,
		empty
	}: {
		queries: QueryLogEntry[];
		filterHref: (by: 'domain' | 'client', value: string) => string;
		empty: string;
	} = $props();

	const table = createTable({
		features,
		columns,
		get data() {
			return queries;
		},
		initialState: { sorting: [{ id: 'time', desc: true }] }
	});

	let kind = $state('all');
	$effect(() => table.getColumn('kind')?.setFilterValue(kind === 'all' ? undefined : kind));
	const kindLabels: Record<string, string> = { all: 'All results', blocked: 'Blocked', allowed: 'Allowed' };

	let rows = $derived(table.getRowModel().rows);

	// The time of day; the date too when it isn't today.
	const timeFormat = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' });
	const dateTimeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' });
	function when(iso: string): string {
		const d = new Date(iso);
		return d.toDateString() === new Date().toDateString() ? timeFormat.format(d) : dateTimeFormat.format(d);
	}

	type SortableId = 'time' | 'domain' | 'client' | 'status' | 'reply';
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

<div class="flex flex-wrap items-center justify-between gap-2">
	<p class="text-muted-foreground text-xs" aria-live="polite">
		{#if kind === 'all'}{queries.length} queries{:else}Showing {rows.length} of {queries.length} queries{/if}
	</p>
	<Select.Root type="single" bind:value={kind}>
		<Select.Trigger class="w-40" aria-label="Result">{kindLabels[kind]}</Select.Trigger>
		<Select.Content>
			{#each Object.entries(kindLabels) as [value, label] (value)}
				<Select.Item {value} {label}>{label}</Select.Item>
			{/each}
		</Select.Content>
	</Select.Root>
</div>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				{@render sortHeader('time', 'Time')}
				<Table.Head>Type</Table.Head>
				{@render sortHeader('domain', 'Domain')}
				{@render sortHeader('client', 'Client')}
				{@render sortHeader('status', 'Status')}
				{@render sortHeader('reply', 'Reply')}
				<Table.Head>Upstream</Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each rows as row (row.id)}
				{@const q = row.original}
				{@const status = describeStatus(q.status)}
				<Table.Row>
					<Table.Cell class="text-sm whitespace-nowrap tabular-nums">
						<time datetime={q.time}>{when(q.time)}</time>
					</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm">{q.type}</Table.Cell>
					<Table.Cell class="max-w-80">
						<a
							href={filterHref('domain', q.domain)}
							class="font-mono text-sm break-all hover:underline"
							title="Only queries for {q.domain}">{q.domain}</a
						>
					</Table.Cell>
					<Table.Cell class="text-sm">
						<a href={filterHref('client', q.client_ip)} class="hover:underline" title="Only queries from {q.client_ip}">
							{#if q.client_name}
								{q.client_name}
								<span class="text-muted-foreground block font-mono text-xs">{q.client_ip}</span>
							{:else}
								<span class="font-mono">{q.client_ip}</span>
							{/if}
						</a>
					</Table.Cell>
					<Table.Cell>
						<Badge variant={status.kind === 'blocked' ? 'destructive' : status.kind === 'allowed' ? 'secondary' : 'outline'}>
							{status.label}
						</Badge>
					</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap tabular-nums">
						{formatReplyTime(q.reply_time_ms)}
					</Table.Cell>
					<Table.Cell class="text-muted-foreground font-mono text-xs">{q.upstream ?? ''}</Table.Cell>
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={7} class="text-muted-foreground py-6 text-center">
						{queries.length > 0 ? 'Nothing matches.' : empty}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
