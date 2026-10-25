<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ClientResetRunDialog from '#lib/components/app/client-reset-run-dialog.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { describeRun, runStatusLabel, type RunList } from '#lib/clientreset.js';
	import { formatDateTime } from '#lib/format.js';

	// The dashboard's client reset card, for someone with clientreset.run on the target: how many rules the target
	// has, its last run, and Run now. `runs` is the target's newest run with its rule count, read by the dashboard's
	// load, so it follows the dashboard's refresh (and shows a scheduled run soon after it happens). `canManage` links
	// to the rules for someone who can change them.
	let {
		target,
		name,
		runs,
		canManage,
		onchange
	}: { target: string; name: string; runs: RunList; canManage: boolean; onchange: () => Promise<void> | void } = $props();

	let open = $state(false);
	let rules = $derived(runs.rules ?? 0);
	let last = $derived(runs.runs[0] ?? null);
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Client reset</Card.Title>
		<Card.Description>Puts clients back in their usual Pi-hole groups, by the start of their comment.</Card.Description>
		{#if rules > 0}
			<Card.Action>
				<Button size="sm" variant="outline" onclick={() => (open = true)}>Run now…</Button>
			</Card.Action>
		{/if}
	</Card.Header>
	<Card.Content class="grid gap-1 text-sm">
		{#if rules === 0}
			<p class="text-muted-foreground">
				No client reset rules are set here, so there's nothing to run.
				{#if canManage}<a class="underline" href="/admin/client-reset">Add rules</a>.{/if}
			</p>
		{:else}
			<p class="text-muted-foreground">
				<!-- The separator is a string: Svelte trims whitespace at the edges of an {#if} block. -->
				{rules === 1 ? '1 rule' : `${rules} rules`}{#if canManage}{' · '}<a class="underline" href="/admin/client-reset"
						>change them</a
					>{/if}
			</p>
			{#if last}
				<p class="flex flex-wrap items-center gap-2" aria-label="Last run">
					<span>Last run {formatDateTime(last.started_at)}</span>
					<span class="text-muted-foreground">by {last.trigger === 'schedule' ? 'the schedule' : last.username}:</span>
					<span>{describeRun(last)}</span>
					<Badge variant={last.status === 'ok' ? 'secondary' : last.status === 'failed' ? 'destructive' : 'outline'}>
						{runStatusLabel[last.status]}
					</Badge>
				</p>
			{:else}
				<p class="text-muted-foreground">Not run yet.</p>
			{/if}
		{/if}
	</Card.Content>
</Card.Root>

{#if rules > 0}
	<ClientResetRunDialog bind:open {target} {name} onran={onchange} />
{/if}
