<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { describeCode, instanceStatusLabel, type InstanceResult } from '#lib/clientreset.js';

	// Each instance's part of a client reset run, or of a preview (`preview` changes the words: "would reset"). Client
	// comments come from the Pi-holes, so they're only ever shown as text.
	let { instances, preview = false }: { instances: InstanceResult[]; preview?: boolean } = $props();

	const statusVariant = (s: InstanceResult['status']) => (s === 'ok' ? 'secondary' : s === 'partial' ? 'outline' : 'destructive');
</script>

<div class="grid gap-3">
	{#each instances as i (i.instance_id)}
		<section class="grid gap-1.5 text-sm" aria-label={i.instance}>
			<div class="flex flex-wrap items-center gap-2">
				<span class="font-medium">{i.instance}</span>
				{#if i.primary}<span class="text-muted-foreground text-xs">primary</span>{/if}
				{#if !preview || i.code}
					<Badge variant={statusVariant(i.status)}>{instanceStatusLabel[i.status]}</Badge>
				{/if}
				{#if i.code}<span class="text-muted-foreground text-xs">{describeCode(i.code)}</span>{/if}
			</div>
			{#if !i.code}
				{#if i.reset.length > 0}
					<p class="text-muted-foreground text-xs">{preview ? 'Would reset' : 'Reset'}:</p>
					<ul class="grid gap-0.5">
						{#each i.reset as c (c.client)}
							<li class="flex flex-wrap gap-x-2 text-xs">
								<span class="font-mono">{c.client}</span>
								<span class="text-muted-foreground">{c.comment}</span>
								<span>{c.groups_before.join(', ') || 'no groups'} → {c.groups_after.join(', ')}</span>
							</li>
						{/each}
					</ul>
				{/if}
				{#if i.failed.length > 0}
					<p class="text-destructive text-xs">{preview ? "Couldn't be reset" : 'Not reset'}:</p>
					<ul class="grid gap-0.5">
						{#each i.failed as f (f.client)}
							<li class="flex flex-wrap gap-x-2 text-xs">
								<span class="font-mono">{f.client}</span>
								<span class="text-muted-foreground">{f.comment}</span>
								<span>{describeCode(f.code)}</span>
							</li>
						{/each}
					</ul>
				{/if}
				{#each i.problems as p (p.prefix)}
					<p class="text-xs text-amber-700 dark:text-amber-400">
						Rule "{p.prefix}": {describeCode(p.code)}{p.missing?.length ? ` (missing ${p.missing.join(', ')})` : ''}.
					</p>
				{/each}
				{#if i.unchanged > 0}
					<p class="text-muted-foreground text-xs">
						{i.unchanged === 1 ? '1 matching client was' : `${i.unchanged} matching clients were`} already in {i.unchanged === 1
							? 'its'
							: 'their'} groups.
					</p>
				{:else if i.reset.length === 0 && i.failed.length === 0 && i.problems.length === 0}
					<p class="text-muted-foreground text-xs">No client matches a rule here.</p>
				{/if}
			{/if}
		</section>
	{/each}
</div>
