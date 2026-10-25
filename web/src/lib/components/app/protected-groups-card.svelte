<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ProtectedGroupsDialog from '#lib/components/app/protected-groups-dialog.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import type { Channel, ProtectedSettings } from '#lib/notifications.js';

	// The protected groups, and which channels receive their alert.
	let {
		settings,
		channels,
		onsaved
	}: { settings: ProtectedSettings; channels: Channel[]; onsaved: () => Promise<void> | void } = $props();

	let open = $state(false);
	let alerted = $derived(channels.filter((c) => c.enabled && c.events.includes('protected_group_add')));
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Protected groups</h2></Card.Title>
		<Card.Description>Pi-hole groups whose new clients raise an alert (protected_group_add).</Card.Description>
		<Card.Action>
			<Button variant="outline" size="sm" onclick={() => (open = true)}>Edit</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content class="grid gap-3">
		{#if settings.entries.length === 0}
			<p class="text-muted-foreground text-sm">None yet.</p>
		{:else}
			<ul class="grid gap-2 text-sm" aria-label="Protected groups">
				{#each settings.entries as e (`${e.scope}:${e.id}`)}
					<li class="flex flex-wrap items-center gap-1.5">
						<span class="font-medium">{e.name}</span>
						<span class="text-muted-foreground text-xs">{e.scope === 'group' ? 'mirrored group' : 'instance'}</span>
						{#each e.pihole_groups as g (g)}<Badge variant="secondary">{g}</Badge>{/each}
					</li>
				{/each}
			</ul>
		{/if}
		<p class={alerted.length === 0 && settings.entries.length > 0 ? 'text-sm text-amber-700 dark:text-amber-400' : 'text-muted-foreground text-sm'}>
			{alerted.length === 0
				? 'No enabled channel receives protected_group_add, so these raise no alert yet.'
				: `Alerts go to ${alerted.map((c) => c.name).join(', ')}.`}
		</p>
	</Card.Content>
</Card.Root>

<ProtectedGroupsDialog bind:open {settings} {onsaved} />
