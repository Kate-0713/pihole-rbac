<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import { SvelteSet } from 'svelte/reactivity';
	import ClientResetResults from '#lib/components/app/client-reset-results.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { describeRun, runStatusLabel, type Run } from '#lib/clientreset.js';
	import { formatDateTime } from '#lib/format.js';

	// Client reset runs, newest first. Each row opens to show what happened on each instance. `showTarget` adds the
	// column naming the instance or group, for the list of every target's runs.
	let { runs, showTarget = true, empty }: { runs: Run[]; showTarget?: boolean; empty: string } = $props();

	// The rows that are open, by run ID. A SvelteSet is Svelte's reactive Set: rows that read it update when an ID is
	// added or removed, which a plain Set wouldn't do.
	const open = new SvelteSet<number>();
	function toggle(id: number) {
		if (open.has(id)) open.delete(id);
		else open.add(id);
	}

	const statusVariant = (s: Run['status']) => (s === 'ok' ? 'secondary' : s === 'failed' ? 'destructive' : 'outline');
	let columns = $derived(showTarget ? 6 : 5);
</script>

{#if runs.length === 0}
	<p class="text-muted-foreground text-sm">{empty}</p>
{:else}
	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head class="w-0"><span class="sr-only">Details</span></Table.Head>
					<Table.Head>Started</Table.Head>
					{#if showTarget}<Table.Head>Instance or group</Table.Head>{/if}
					<Table.Head>By</Table.Head>
					<Table.Head>Result</Table.Head>
					<Table.Head>Status</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each runs as r (r.id)}
					{@const isOpen = open.has(r.id)}
					<Table.Row data-run={r.id}>
						<Table.Cell class="pr-0">
							<button
								type="button"
								class="text-muted-foreground hover:text-foreground grid size-6 cursor-pointer place-items-center rounded"
								aria-expanded={isOpen}
								aria-controls="reset-run-{r.id}"
								aria-label="{isOpen ? 'Hide' : 'Show'} the details of the run of {r.target_name}"
								onclick={() => toggle(r.id)}
							>
								<ChevronRightIcon class="size-4 transition-transform {isOpen ? 'rotate-90' : ''}" />
							</button>
						</Table.Cell>
						<Table.Cell class="whitespace-nowrap">{formatDateTime(r.started_at)}</Table.Cell>
						{#if showTarget}<Table.Cell>{r.target_name}</Table.Cell>{/if}
						<Table.Cell>{r.trigger === 'schedule' ? 'Schedule' : r.username}</Table.Cell>
						<Table.Cell class="max-w-72 truncate" title={describeRun(r)}>{describeRun(r)}</Table.Cell>
						<Table.Cell><Badge variant={statusVariant(r.status)}>{runStatusLabel[r.status]}</Badge></Table.Cell>
					</Table.Row>
					{#if isOpen}
						<Table.Row id="reset-run-{r.id}" class="bg-muted/40 hover:bg-muted/40">
							<Table.Cell colspan={columns} class="whitespace-normal">
								{#if r.instances.length === 0}
									<p class="text-muted-foreground text-xs">{r.error ?? 'No instance was reached.'}</p>
								{:else}
									<ClientResetResults instances={r.instances} />
								{/if}
								<p class="text-muted-foreground mt-2 text-xs">
									Run #{r.id} · {r.rules === 1 ? '1 rule' : `${r.rules} rules`}{r.finished_at
										? ` · finished ${formatDateTime(r.finished_at)}`
										: ''}
								</p>
							</Table.Cell>
						</Table.Row>
					{/if}
				{/each}
			</Table.Body>
		</Table.Root>
	</div>
{/if}
