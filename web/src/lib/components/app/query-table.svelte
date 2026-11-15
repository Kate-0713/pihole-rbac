<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts" module>
	import { columnVisibilityFeature, createColumnHelper, tableFeatures } from '@tanstack/svelte-table';
	import { describeStatus, hideableColumns, type ColumnId, type QueryLogEntry } from '#lib/queries.js';

	// The log comes from the server a page at a time, already filtered and newest first, so the table only shows it;
	// the one table feature is choosing columns.
	const features = tableFeatures({ columnVisibilityFeature });
	const column = createColumnHelper<typeof features, QueryLogEntry>();
	const columns = column.columns(
		(Object.keys(hideableColumns) as ColumnId[]).map((id) => column.display({ id, header: hideableColumns[id] }))
	);
</script>

<script lang="ts">
	import { createTable } from '@tanstack/svelte-table';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import CellText from '#lib/components/app/cell-text.svelte';
	import * as Table from '#lib/components/ui/table/index.js';
	import { formatReplyTime } from '#lib/queries.js';

	// filterHref gives the link that filters the log by a domain or client, so a value in the table can be clicked
	// to narrow the log to it. empty is what to say when the page has no entries. showInstance allows the column
	// naming the instance that answered, for a mirrored group. visibility is the columns chosen, by ID; only an
	// explicit false hides one.
	let {
		queries,
		filterHref,
		empty,
		showInstance = false,
		visibility
	}: {
		queries: QueryLogEntry[];
		filterHref: (by: 'domain' | 'client', value: string) => string;
		empty: string;
		showInstance?: boolean;
		visibility: Record<string, boolean>;
	} = $props();

	const table = createTable({
		features,
		columns,
		get data() {
			return queries;
		},
		state: {
			get columnVisibility() {
				return { ...visibility, instance: showInstance && visibility.instance !== false };
			}
		}
	});

	let shown = $derived(table.getVisibleLeafColumns().map((c) => c.id as ColumnId));

	// The time of day; the date too when it isn't today.
	const timeFormat = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' });
	const dateTimeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' });
	function when(iso: string): string {
		const d = new Date(iso);
		return d.toDateString() === new Date().toDateString() ? timeFormat.format(d) : dateTimeFormat.format(d);
	}
</script>

{#snippet cell(id: ColumnId, q: QueryLogEntry)}
	{#if id === 'time'}
		<Table.Cell class="text-sm whitespace-nowrap tabular-nums"><time datetime={q.time}>{when(q.time)}</time></Table.Cell>
	{:else if id === 'instance'}
		<Table.Cell class="text-sm whitespace-nowrap">{q.instance}</Table.Cell>
	{:else if id === 'type'}
		<Table.Cell class="text-muted-foreground text-sm">{q.type}</Table.Cell>
	{:else if id === 'domain'}
		<Table.Cell>
			<CellText width="lg">
				<a href={filterHref('domain', q.domain)} class="font-mono text-sm hover:underline" title="Only queries for {q.domain}"
					>{q.domain}</a
				>
			</CellText>
		</Table.Cell>
	{:else if id === 'client'}
		<Table.Cell class="text-sm">
			<CellText>
				<a href={filterHref('client', q.client_ip)} class="hover:underline" title="Only queries from {q.client_ip}">
					{#if q.client_name}
						{q.client_name}
						<span class="text-muted-foreground block font-mono text-xs">{q.client_ip}</span>
					{:else}
						<span class="font-mono">{q.client_ip}</span>
					{/if}
				</a>
			</CellText>
		</Table.Cell>
	{:else if id === 'status'}
		{@const status = describeStatus(q.status)}
		<Table.Cell>
			<Badge variant={status.kind === 'blocked' ? 'destructive' : status.kind === 'allowed' ? 'secondary' : 'outline'}>
				{status.label}
			</Badge>
		</Table.Cell>
	{:else if id === 'reply'}
		<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap tabular-nums">{formatReplyTime(q.reply_time_ms)}</Table.Cell>
	{:else}
		<Table.Cell class="text-muted-foreground font-mono text-xs"><CellText>{q.upstream ?? ''}</CellText></Table.Cell>
	{/if}
{/snippet}

<div class="overflow-x-auto rounded-lg border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				{#each shown as id (id)}
					<Table.Head>{hideableColumns[id]}</Table.Head>
				{/each}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each queries as q, i (i)}
				<Table.Row>
					{#each shown as id (id)}
						{@render cell(id, q)}
					{/each}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={Math.max(shown.length, 1)} class="text-muted-foreground py-6 text-center">{empty}</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
