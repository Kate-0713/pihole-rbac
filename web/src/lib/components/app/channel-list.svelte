<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import {
		canReplaceSecret,
		describeDestination,
		describeSecret,
		eventsSummary,
		kindLabel,
		secretWord,
		type Channel
	} from '#lib/notifications.js';

	// The channels, a list item each rather than a table row: a channel has several lines of detail, and it reads
	// better on a phone. Each has a menu of what can be done with it.
	let {
		channels,
		canStoreSecrets,
		busy,
		ontest,
		onedit,
		onsecret,
		onenable,
		ondisable,
		ondelete
	}: {
		channels: Channel[];
		canStoreSecrets: boolean;
		busy: number | null; // the channel a test or enable is running on
		ontest: (c: Channel) => void;
		onedit: (c: Channel) => void;
		onsecret: (c: Channel) => void;
		onenable: (c: Channel) => void;
		ondisable: (c: Channel) => void;
		ondelete: (c: Channel) => void;
	} = $props();
</script>

<ul class="divide-y rounded-md border">
	{#each channels as c (c.id)}
		{@const secret = describeSecret(c)}
		<li class="flex items-start justify-between gap-3 p-3" data-channel={c.name}>
			<div class="grid min-w-0 gap-1 text-sm">
				<p class="flex flex-wrap items-center gap-1.5">
					<span class="font-medium">{c.name}</span>
					<Badge variant="outline">{kindLabel[c.kind]}</Badge>
					{#if c.enabled}
						<Badge variant="secondary">Enabled</Badge>
					{:else}
						<Badge variant="destructive">Disabled</Badge>
					{/if}
				</p>
				<p class="text-muted-foreground font-mono text-xs break-all">{describeDestination(c)}</p>
				<p class={secret.problem ? 'text-destructive text-xs' : 'text-muted-foreground text-xs'}>{secret.text}</p>
				<p class="text-muted-foreground text-xs" title={c.events.join(', ')}>{eventsSummary(c.events)}</p>
			</div>
			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					{#snippet child({ props })}
						<Button {...props} variant="ghost" size="icon" disabled={busy === c.id} aria-label="Actions for {c.name}">
							<EllipsisIcon />
						</Button>
					{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Content align="end">
					<DropdownMenu.Item disabled={!!c.secret_problem} onSelect={() => ontest(c)}>Send test</DropdownMenu.Item>
					<DropdownMenu.Item onSelect={() => onedit(c)}>Edit</DropdownMenu.Item>
					{#if canReplaceSecret(c, canStoreSecrets)}
						<DropdownMenu.Item onSelect={() => onsecret(c)}>
							{c.secret_source === 'none' ? 'Set' : 'Replace'} {secretWord(c.kind)}
						</DropdownMenu.Item>
					{/if}
					{#if c.enabled}
						<DropdownMenu.Item onSelect={() => ondisable(c)}>Disable</DropdownMenu.Item>
					{:else}
						<DropdownMenu.Item onSelect={() => onenable(c)}>Enable</DropdownMenu.Item>
					{/if}
					<DropdownMenu.Separator />
					<DropdownMenu.Item variant="destructive" onSelect={() => ondelete(c)}>Delete</DropdownMenu.Item>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		</li>
	{/each}
</ul>
