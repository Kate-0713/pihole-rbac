<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { countText, describeReference, hiddenCount, reasonText, type GroupReferences } from '#lib/pihole-groups.js';

	// The app's references to a Pi-hole group: how many, and the ones the user manages (client reset rules with
	// settings.manage, protected groups with notifications.manage, schedules with schedules.manage on their target).
	// The server leaves the others out of `items`, so this only says how many it can't show. Every value is shown
	// as text.
	let { refs, label }: { refs: GroupReferences; label: string } = $props();

	let hidden = $derived(hiddenCount(refs));
</script>

<div class="grid gap-1 text-sm" data-references={label}>
	<p><span class="font-medium">{label}:</span> {countText(refs)}.</p>
	{#if refs.items.length > 0}
		<ul class="text-muted-foreground list-disc space-y-0.5 pl-5">
			{#each refs.items as r, i (i)}
				<li class="wrap-anywhere">
					{describeReference(r)}
					{#if r.before}<span> (was {r.before.join(', ')})</span>{/if}
					{#if r.dropped}<span> (removed: the new name was already listed)</span>{/if}
					{#if r.reason}<span> ({reasonText[r.reason]})</span>{/if}
				</li>
			{/each}
		</ul>
	{/if}
	{#if hidden > 0}
		<p class="text-muted-foreground">
			{hidden === 1 ? 'One of them is' : `${hidden} of them are`} managed by someone with more access, so not shown.
		</p>
	{/if}
</div>
