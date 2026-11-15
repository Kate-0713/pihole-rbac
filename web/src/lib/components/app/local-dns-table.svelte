<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import CellText from '#lib/components/app/cell-text.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { markHint, markLabel, writable, type LocalDNSKind, type Row } from '#lib/local-dns.js';

	// One table of local DNS entries: host records or CNAMEs. They're short lists with no settings to filter on, so
	// this is a plain table with a search box, sorted by name, rather than the TanStack table the domain lists use.
	let {
		kind,
		rows,
		canEdit,
		onedit,
		ondelete
	}: {
		kind: LocalDNSKind;
		rows: Row[];
		// Whether the entries can be changed here (the permission, and an instance that lets the app).
		canEdit: boolean;
		onedit: (r: Row) => void;
		ondelete: (r: Row) => void;
	} = $props();

	let search = $state('');
	let id = $derived(`local-dns-${kind}`);
	let what = $derived(kind === 'record' ? 'records' : 'CNAMEs');

	// $derived re-runs whenever rows or search change; the sorted copy leaves the prop itself alone.
	let shown = $derived.by(() => {
		const q = search.trim().toLowerCase();
		const match = (r: Row) =>
			q === '' ||
			[r.name, r.points, r.value, ...r.extra, r.comment ?? '', r.reason?.reason ?? ''].some((s) => s.toLowerCase().includes(q));
		return rows.filter(match).toSorted((a, b) => a.name.localeCompare(b.name) || a.points.localeCompare(b.points));
	});
	let cols = $derived(4 + (kind === 'cname' ? 1 : 0) + (canEdit ? 1 : 0));
</script>

<div class="flex flex-wrap items-end gap-2">
	<div class="grid min-w-48 flex-1 gap-1">
		<label for="{id}-search" class="text-muted-foreground text-xs">Search {what}</label>
		<Input id="{id}-search" type="search" bind:value={search} autocomplete="off" />
	</div>
</div>
<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if search.trim() !== ''}Showing {shown.length} of {rows.length} {what}{:else}{rows.length} {what}{/if}
</p>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root aria-label={kind === 'record' ? 'Records' : 'CNAMEs'}>
		<Table.Header>
			<Table.Row>
				<Table.Head>{kind === 'record' ? 'Hostname' : 'Alias'}</Table.Head>
				<Table.Head>{kind === 'record' ? 'Address' : 'Target'}</Table.Head>
				{#if kind === 'cname'}<Table.Head>TTL</Table.Head>{/if}
				<Table.Head>Reason</Table.Head>
				<Table.Head>Last changed</Table.Head>
				{#if canEdit}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each shown as r (r.value)}
				<Table.Row data-entry={r.key}>
					<Table.Cell>
						<CellText width="lg">
							<span class="font-mono text-sm">{r.name}</span>
							{#if r.extra.length > 0}
								<span class="text-muted-foreground block font-mono text-xs">also {r.extra.join(', ')}</span>
							{/if}
							{#if r.marks.length > 0}
								<span class="mt-1 flex flex-wrap gap-1">
									{#each r.marks as m (m)}
										<Badge
											variant="outline"
											class={m === 'unparsed' ? 'border-amber-500 text-amber-700 dark:text-amber-400' : ''}
											title={markHint[m]}>{markLabel[m]}</Badge
										>
									{/each}
								</span>
								<span class="text-muted-foreground block font-mono text-xs break-all">{r.value}</span>
							{/if}
						</CellText>
					</Table.Cell>
					<Table.Cell><CellText><span class="font-mono text-sm">{r.points || '—'}</span></CellText></Table.Cell>
					{#if kind === 'cname'}
						<Table.Cell class="text-sm tabular-nums">{r.ttl !== undefined ? `${r.ttl}s` : 'Default'}</Table.Cell>
					{/if}
					<Table.Cell class="text-sm">
						<CellText>
							{#if r.reason}
								{r.reason.reason || 'No reason given'}
								<span class="text-muted-foreground block text-xs">by {r.reason.by}</span>
							{:else}
								<span class="text-muted-foreground">No reason recorded</span>
							{/if}
						</CellText>
					</Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap">
						{r.reason ? formatDateTime(r.reason.at) : '—'}
					</Table.Cell>
					{#if canEdit}
						<Table.Cell class="text-right whitespace-nowrap">
							<Button
								variant="ghost"
								size="sm"
								onclick={() => onedit(r)}
								aria-label="{writable(r) ? 'Change' : 'Replace'} {r.name}">{writable(r) ? 'Change' : 'Replace'}</Button
							>
							<Button variant="ghost" size="sm" class="text-destructive" onclick={() => ondelete(r)} aria-label="Delete {r.name}"
								>Delete</Button
							>
						</Table.Cell>
					{/if}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={cols} class="text-muted-foreground py-6 text-center">
						{search.trim() !== '' ? 'Nothing matches.' : `No ${what} yet.`}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
