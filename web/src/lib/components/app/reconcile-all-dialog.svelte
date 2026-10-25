<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { plan, type DriftReport } from '#lib/drift.js';

	// Asks before making every member match the primary, listing what will change on each, since entries and clients
	// only a member has are deleted. The list comes from the last report; the server compares again when it runs.
	let {
		open = $bindable(false),
		report,
		busy,
		onconfirm
	}: { open: boolean; report: DriftReport; busy: boolean; onconfirm: () => void } = $props();

	let p = $derived(plan(report));
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content class="max-h-[90dvh] overflow-y-auto">
		<AlertDialog.Header>
			<AlertDialog.Title>Make every member of {report.group} match the primary?</AlertDialog.Title>
			<AlertDialog.Description>
				Each member is read again and changed to match the primary. Entries and clients only a member has are
				deleted.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<div class="grid gap-3 text-sm">
			{#each p.members as m (m.member)}
				<div>
					<p class="font-medium">{m.member}</p>
					<ul class="text-muted-foreground list-disc pl-5">
						{#each m.lines as line (line)}<li>{line}</li>{/each}
					</ul>
				</div>
			{/each}
			{#if p.hidden.length > 0}
				<p class="text-muted-foreground">
					Also {p.hidden.join(' and ')} you can't see, which will be made to match as well.
				</p>
			{/if}
			{#if p.keptGroups > 0}
				<p class="text-muted-foreground">
					{p.keptGroups === 1 ? '1 Pi-hole group' : `${p.keptGroups} Pi-hole groups`} only a member has will be kept:
					Pi-hole groups are never deleted.
				</p>
			{/if}
		</div>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action
				class={buttonVariants({ variant: 'destructive' })}
				disabled={busy}
				onclick={(e: MouseEvent) => {
					// Kept open until the reconcile has answered.
					e.preventDefault();
					onconfirm();
				}}
			>
				{busy ? 'Reconciling…' : 'Reconcile all'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
