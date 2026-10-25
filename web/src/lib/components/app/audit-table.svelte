<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import { SvelteSet } from 'svelte/reactivity';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { detailText, errorOf, type AuditEntry, type AuditFilters } from '#lib/audit.js';
	import { formatDateTime } from '#lib/format.js';

	// The audit entries, newest first, as the server sends them. A user, action, target or instance is a link that
	// filters by it (filterHref gives its URL). Each row opens to show its detail, address and exact time.
	let {
		entries,
		filterHref,
		empty
	}: {
		entries: AuditEntry[];
		filterHref: (change: Partial<AuditFilters>) => string;
		empty: string;
	} = $props();

	// The rows that are open, by entry ID. SvelteSet updates the rows that read it when an ID is added or removed.
	const open = new SvelteSet<number>();
	function toggle(id: number) {
		if (open.has(id)) open.delete(id);
		else open.add(id);
	}

	const link = 'hover:underline underline-offset-2';
</script>

{#if entries.length === 0}
	<p class="text-muted-foreground text-sm">{empty}</p>
{:else}
	<!-- On a phone the table scrolls sideways inside its own box rather than widening the page. -->
	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head class="w-0"><span class="sr-only">Details</span></Table.Head>
					<Table.Head>Time</Table.Head>
					<Table.Head>User</Table.Head>
					<Table.Head>Action</Table.Head>
					<Table.Head>Target</Table.Head>
					<Table.Head>Instance</Table.Head>
					<Table.Head>Result</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each entries as e (e.id)}
					{@const isOpen = open.has(e.id)}
					{@const error = errorOf(e)}
					<Table.Row data-entry={e.id}>
						<Table.Cell class="pr-0">
							<button
								type="button"
								class="text-muted-foreground hover:text-foreground grid size-6 cursor-pointer place-items-center rounded"
								aria-expanded={isOpen}
								aria-controls="audit-detail-{e.id}"
								aria-label="{isOpen ? 'Hide' : 'Show'} the details of {e.action} by {e.username}"
								onclick={() => toggle(e.id)}
							>
								<ChevronRightIcon class="size-4 transition-transform {isOpen ? 'rotate-90' : ''}" />
							</button>
						</Table.Cell>
						<Table.Cell class="whitespace-nowrap">{formatDateTime(e.at)}</Table.Cell>
						<Table.Cell>
							<a class={link} href={filterHref({ user: e.username })} title="Only entries by {e.username}">{e.username}</a>
						</Table.Cell>
						<Table.Cell class="font-mono text-xs">
							<a class={link} href={filterHref({ actions: [e.action] })} title="Only {e.action} entries">{e.action}</a>
						</Table.Cell>
						<Table.Cell class="max-w-56 truncate font-mono text-xs">
							{#if e.target}
								<a class={link} href={filterHref({ target: e.target })} title={e.target}>{e.target}</a>
							{/if}
						</Table.Cell>
						<Table.Cell>
							{#if e.instance_id !== undefined}
								<a class={link} href={filterHref({ instanceId: e.instance_id })} title="Only entries about {e.instance_name}"
									>{e.instance_name}</a
								>
							{:else if e.instance_name}
								<!-- The instance has since been deleted: its name is kept, but there's nothing to filter by. -->
								<span class="text-muted-foreground" title="Deleted">{e.instance_name}</span>
							{/if}
						</Table.Cell>
						<Table.Cell>
							{#if e.result === 'failure'}
								<Badge variant="destructive">Failed</Badge>
								{#if error}<p class="text-muted-foreground mt-1 max-w-64 truncate text-xs" title={error}>{error}</p>{/if}
							{:else}
								<Badge variant="secondary">OK</Badge>
							{/if}
						</Table.Cell>
					</Table.Row>
					{#if isOpen}
						<Table.Row id="audit-detail-{e.id}" class="bg-muted/40 hover:bg-muted/40">
							<Table.Cell colspan={7} class="whitespace-normal">
								<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
									<dt class="text-muted-foreground">Time (UTC)</dt>
									<dd class="font-mono">{e.at}</dd>
									<dt class="text-muted-foreground">Address</dt>
									<dd class="font-mono">{e.ip || '—'}</dd>
									<dt class="text-muted-foreground">Entry</dt>
									<dd class="font-mono">#{e.id}</dd>
									{#if e.instance_name && e.instance_id === undefined}
										<dt class="text-muted-foreground">Instance</dt>
										<dd>{e.instance_name} (since deleted)</dd>
									{/if}
								</dl>
								{#if detailText(e.detail)}
									<!-- Shown as text: details hold Pi-hole comments, usernames and other values from outside. -->
									<pre class="bg-background mt-2 max-h-80 overflow-auto rounded border p-2 font-mono text-xs">{detailText(
											e.detail
										)}</pre>
								{/if}
							</Table.Cell>
						</Table.Row>
					{/if}
				{/each}
			</Table.Body>
		</Table.Root>
	</div>
{/if}
