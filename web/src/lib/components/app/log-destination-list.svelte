<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { describeStatus, stateLabel, transportLabel, where, type LogDestination } from '#lib/logdestinations.js';

	// The destinations, a list item each rather than a table row: a destination has several lines of status, and it
	// reads better on a phone. Each has a menu of what can be done with it.
	let {
		destinations,
		busy,
		ontest,
		onedit,
		onenable,
		ondisable,
		ondelete
	}: {
		destinations: LogDestination[];
		busy: number | null; // the destination a test or enable is running on
		ontest: (d: LogDestination) => void;
		onedit: (d: LogDestination) => void;
		onenable: (d: LogDestination) => void;
		ondisable: (d: LogDestination) => void;
		ondelete: (d: LogDestination) => void;
	} = $props();
</script>

<ul class="divide-y rounded-md border">
	{#each destinations as d (d.id)}
		<li class="flex items-start justify-between gap-3 p-3" data-destination={d.name}>
			<div class="grid min-w-0 gap-1 text-sm">
				<p class="flex flex-wrap items-center gap-1.5">
					<span class="font-medium">{d.name}</span>
					<Badge variant={d.status.state === 'failing' ? 'destructive' : d.status.state === 'ok' ? 'secondary' : 'outline'}>
						{stateLabel[d.status.state]}
					</Badge>
					<Badge variant={d.transport === 'tls' ? 'outline' : 'destructive'}>{transportLabel[d.transport]}</Badge>
					{#if d.transport === 'tls' && d.tls_mode === 'insecure'}
						<Badge variant="destructive">Certificate not checked</Badge>
					{/if}
				</p>
				<p class="text-muted-foreground font-mono text-xs break-all">{where(d)}</p>
				{#each describeStatus(d) as line (line.text)}
					<p class={line.problem ? 'text-destructive text-xs' : 'text-muted-foreground text-xs'}>{line.text}</p>
				{/each}
			</div>
			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					{#snippet child({ props })}
						<Button {...props} variant="ghost" size="icon" disabled={busy === d.id} aria-label="Actions for {d.name}">
							<EllipsisIcon />
						</Button>
					{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Content align="end">
					<DropdownMenu.Item onSelect={() => ontest(d)}>Send test</DropdownMenu.Item>
					<DropdownMenu.Item onSelect={() => onedit(d)}>Edit</DropdownMenu.Item>
					{#if d.enabled}
						<DropdownMenu.Item onSelect={() => ondisable(d)}>Disable</DropdownMenu.Item>
					{:else}
						<DropdownMenu.Item onSelect={() => onenable(d)}>Enable</DropdownMenu.Item>
					{/if}
					<DropdownMenu.Separator />
					<DropdownMenu.Item variant="destructive" onSelect={() => ondelete(d)}>Delete</DropdownMenu.Item>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		</li>
	{/each}
</ul>
