<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { badgeOf, memberText, remainingText, type TempChange } from '#lib/temp-changes.js';

	// What a client's row says about its temporary change: a badge, how long is left and why, and, once something has
	// gone wrong putting the client back, what each instance did. A badge's colour isn't the only signal: its words
	// ("Overdue, reverting", "Revert failed") say the same.
	let { change, now }: { change: TempChange; now: Date } = $props();

	let badge = $derived(badgeOf(change, formatDateTime));
	// Members worth a line: any that isn't put back yet once the time is up, or that went wrong.
	let trouble = $derived(
		change.overdue || change.status === 'failed' ? change.members.filter((m) => m.revert_status !== 'ok') : []
	);
</script>

{#if badge}
	<div class="mt-1 grid gap-0.5">
		<div class="flex flex-wrap items-center gap-2">
			<Badge variant={badge.kind === 'overdue' || badge.kind === 'failed' ? 'destructive' : 'secondary'}>{badge.label}</Badge>
			{#if change.status === 'active' && !change.overdue}
				<span class="text-muted-foreground text-xs">{remainingText(change.ends_at, now)}</span>
			{/if}
		</div>
		{#if change.reason}<p class="text-muted-foreground text-xs">“{change.reason}” · {change.created_by}</p>{/if}
		{#each trouble as m (m.instance_id)}
			<p class="text-destructive text-xs">{memberText(m)}</p>
		{/each}
	</div>
{/if}
