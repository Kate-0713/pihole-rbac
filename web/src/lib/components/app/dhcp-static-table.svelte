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
	import { markHint, markLabel, type DHCPStaticLease } from '#lib/dhcp.js';

	// Static leases: a hardware address always given the same address (and name). An entry the app couldn't have
	// written is marked and can be deleted or replaced, not changed in place, as for local DNS.
	export type StaticRow = DHCPStaticLease & { instance: string; instance_id: number };

	let {
		rows,
		showInstance,
		onedit,
		ondelete
	}: {
		rows: StaticRow[];
		showInstance: boolean;
		// Both are given only where the user may change this instance's static leases.
		onedit?: (r: StaticRow) => void;
		ondelete?: (r: StaticRow) => void;
	} = $props();

	let search = $state('');
	let shown = $derived.by(() => {
		const q = search.trim().toLowerCase();
		const match = (r: StaticRow) =>
			q === '' || [r.mac ?? '', r.ip ?? '', r.hostname ?? '', r.value, r.instance].some((s) => s.toLowerCase().includes(q));
		return rows.filter(match);
	});
	let actions = $derived(!!onedit || !!ondelete);
	let cols = $derived(3 + (showInstance ? 1 : 0) + (actions ? 1 : 0));
	const writable = (r: StaticRow) => r.marks.length === 0;
</script>

<div class="flex flex-wrap items-end gap-2">
	<div class="grid min-w-48 flex-1 gap-1">
		<label for="dhcp-static-search" class="text-muted-foreground text-xs">Search static leases by address, MAC or name</label>
		<Input id="dhcp-static-search" type="search" bind:value={search} autocomplete="off" />
	</div>
</div>
<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if search.trim() !== ''}Showing {shown.length} of {rows.length} static leases{:else}{rows.length} static leases{/if}
</p>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root aria-label="Static leases">
		<Table.Header>
			<Table.Row>
				{#if showInstance}<Table.Head>Pi-hole</Table.Head>{/if}
				<Table.Head>Hardware address</Table.Head>
				<Table.Head>Address</Table.Head>
				<Table.Head>Name</Table.Head>
				{#if actions}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each shown as r (`${r.instance_id} ${r.value}`)}
				<Table.Row data-static={r.key}>
					{#if showInstance}<Table.Cell class="text-sm">{r.instance}</Table.Cell>{/if}
					<Table.Cell>
						<CellText width="lg">
							<span class="font-mono text-sm">{r.mac ?? '—'}</span>
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
					<Table.Cell class="font-mono text-sm">{r.ip ?? '—'}</Table.Cell>
					<Table.Cell class="text-sm"><CellText>{r.hostname ?? '—'}</CellText></Table.Cell>
					{#if actions}
						<Table.Cell class="text-right whitespace-nowrap">
							{#if onedit}
								<Button
									variant="ghost"
									size="sm"
									onclick={() => onedit(r)}
									aria-label="{writable(r) ? 'Change' : 'Replace'} {r.mac ?? r.value}">{writable(r) ? 'Change' : 'Replace'}</Button
								>
							{/if}
							{#if ondelete}
								<Button
									variant="ghost"
									size="sm"
									class="text-destructive"
									onclick={() => ondelete(r)}
									aria-label="Delete {r.mac ?? r.value}">Delete</Button
								>
							{/if}
						</Table.Cell>
					{/if}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={cols} class="text-muted-foreground py-6 text-center">
						{search.trim() !== '' ? 'Nothing matches.' : 'No static leases yet.'}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
