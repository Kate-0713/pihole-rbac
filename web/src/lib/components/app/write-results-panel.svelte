<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import XIcon from '@lucide/svelte/icons/x';
	import { summarise } from '#lib/api/results.js';
	import { Alert, AlertDescription, AlertTitle } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { writeResults } from '#lib/stores/write-results.svelte.js';

	// A write through a mirrored group that didn't work on every member: each member's result, and a retry for those
	// that failed. It stays until dismissed or until a retry works everywhere.
	const labels = { ok: 'Done', failed: 'Failed', skipped: 'Not reached' } as const;

	let panel = $derived(writeResults.panel);
	let summary = $derived(panel ? summarise(panel.results) : null);
</script>

{#if panel && summary}
	<Alert class="pr-12" aria-live="polite">
		<AlertTitle>
			{summary.ok.length > 0 ? `${panel.done} on ${summary.ok.length} of ${panel.results.length} members` : panel.failed}
		</AlertTitle>
		<AlertDescription>
			<ul class="mt-1 grid w-full gap-1.5" aria-label="Results per member">
				{#each panel.results as r (r.instance_id)}
					<li class="flex flex-wrap items-baseline gap-x-2">
						<span class="text-foreground font-medium">{r.instance}</span>
						<Badge variant={r.status === 'ok' ? 'secondary' : 'destructive'}>{labels[r.status]}</Badge>
						{#if r.error}<span class="text-sm">{r.error.message}</span>{/if}
					</li>
				{/each}
			</ul>
			<div class="mt-3 flex flex-wrap gap-2">
				<Button size="sm" disabled={writeResults.busy} onclick={() => writeResults.retry()}>
					{writeResults.busy
						? 'Retrying…'
						: `Retry ${summary.failed.length + summary.skipped.length === 1 ? 'the failed member' : 'the failed members'}`}
				</Button>
			</div>
		</AlertDescription>
		<Button
			variant="ghost"
			size="icon-sm"
			class="absolute top-1.5 right-1.5"
			aria-label="Dismiss"
			disabled={writeResults.busy}
			onclick={() => writeResults.dismiss()}
		>
			<XIcon />
		</Button>
	</Alert>
{/if}
