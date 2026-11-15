<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import CellText from '#lib/components/app/cell-text.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { describeWhen, kindLabel, lengthText, resultText, troubled, type Schedule } from '#lib/schedules.js';

	// A target's schedules. A row opens to show each instance's result for the latest edge. Times are shown in the
	// browser's zone; a weekly schedule's own times are in its zone, which the row names when it differs. With canEdit
	// every row can be deleted, and changed or switched on and off where canChange says so: that needs the permission
	// for what the schedule does, which a delete doesn't.
	let {
		schedules,
		label,
		browser,
		canEdit,
		canChange = () => false,
		onedit,
		ondelete,
		ontoggle
	}: {
		schedules: Schedule[];
		label: string;
		browser: string;
		canEdit: boolean;
		canChange?: (s: Schedule) => boolean;
		onedit?: (s: Schedule) => void;
		ondelete?: (s: Schedule) => void;
		ontoggle?: (s: Schedule) => void;
	} = $props();

	let openRows = $state<Record<number, boolean>>({});
	const at = (iso: string | undefined) => formatDateTime(iso);
	let cols = $derived(5 + (canEdit ? 1 : 0));
</script>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root aria-label={label}>
		<Table.Header>
			<Table.Row>
				<Table.Head>Name</Table.Head>
				<Table.Head>What</Table.Head>
				<Table.Head>When</Table.Head>
				<Table.Head>Next</Table.Head>
				<Table.Head>Status</Table.Head>
				{#if canEdit}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each schedules as s (s.id)}
				<Table.Row data-schedule={s.name}>
					<Table.Cell><CellText width="md">{s.name}</CellText></Table.Cell>
					<Table.Cell>
						{kindLabel[s.kind]}
						{#if s.pihole_group}<span class="block font-mono text-xs">{s.pihole_group}</span>{/if}
					</Table.Cell>
					<Table.Cell>
						<CellText width="lg">
							{describeWhen(s, (iso) => at(iso))}
							<span class="text-muted-foreground block text-xs">
								{lengthText(s.length_minutes)}{s.time_zone && s.time_zone !== browser ? ` · ${s.time_zone}` : ''}
							</span>
						</CellText>
					</Table.Cell>
					<Table.Cell class="text-sm">
						{#if s.finished_at}
							<span class="text-muted-foreground">Finished {at(s.finished_at)}</span>
						{:else if !s.enabled}
							<span class="text-muted-foreground">Off</span>
						{:else if s.next_edge}
							{s.next_edge.edge === 'start' ? 'Starts' : 'Ends'} {at(s.next_edge.at)}
						{:else}
							<span class="text-muted-foreground">—</span>
						{/if}
					</Table.Cell>
					<Table.Cell>
						<span class="flex flex-wrap items-center gap-1">
							{#if s.open}<Badge>Open until {at(s.open_until)}</Badge>{/if}
							{#if s.over_limit}<Badge variant="outline" title="Longer than the limit now allows; a change must shorten it">Over the limit</Badge>{/if}
							{#if troubled(s)}
								<Badge variant="destructive">Needs a look</Badge>
							{:else if s.results.length > 0}
								<span class="text-muted-foreground text-xs">{s.last_edge?.edge === 'start' ? 'Started' : 'Ended'} {at(s.last_edge?.at)}</span>
							{/if}
							{#if s.results.length > 0}
								<Button
									variant="link"
									size="sm"
									class="h-auto p-0 text-xs"
									aria-expanded={!!openRows[s.id]}
									onclick={() => (openRows[s.id] = !openRows[s.id])}
								>
									{openRows[s.id] ? 'Hide' : 'Details'}
								</Button>
							{/if}
						</span>
					</Table.Cell>
					{#if canEdit}
						<Table.Cell class="text-right whitespace-nowrap">
							{#if !s.finished_at && canChange(s)}
								<Button variant="ghost" size="sm" onclick={() => ontoggle?.(s)}>{s.enabled ? 'Switch off' : 'Switch on'}</Button>
								<Button variant="ghost" size="sm" onclick={() => onedit?.(s)}>Change</Button>
							{/if}
							<Button variant="ghost" size="sm" onclick={() => ondelete?.(s)}>Delete</Button>
						</Table.Cell>
					{/if}
				</Table.Row>
				{#if openRows[s.id]}
					<Table.Row>
						<Table.Cell colspan={cols} class="bg-muted/40">
							<ul class="grid gap-1 text-sm" aria-label="Results of {s.name}">
								{#each s.results as r (r.instance_id)}
									<li>
										<span class="font-medium">{r.instance}</span>:
										<span class={r.status === 'ok' ? '' : 'text-destructive'}>{resultText(r)}</span>
										<span class="text-muted-foreground text-xs">· {at(r.at)}</span>
									</li>
								{/each}
							</ul>
						</Table.Cell>
					</Table.Row>
				{/if}
			{:else}
				<Table.Row>
					<Table.Cell colspan={cols} class="text-muted-foreground text-center text-sm">No schedules.</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
