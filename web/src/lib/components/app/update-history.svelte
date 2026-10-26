<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { isActive, requestStatusLabel, requestTarget, type UpdateRequest } from '#lib/system.js';

	// The latest update requests, newest first, each with the updater's log. A request still in progress is shown
	// open, so its log can be watched as it grows.
	let { requests }: { requests: UpdateRequest[] } = $props();

	const variant = (s: UpdateRequest['status']) =>
		s === 'done' ? 'secondary' : s === 'failed' || s === 'rolled_back' ? 'destructive' : 'outline';
</script>

{#if requests.length > 0}
	<ul class="grid gap-2" aria-label="Update history">
		{#each requests as r (r.id)}
			<li class="rounded-md border p-3 text-sm" data-request={r.id}>
				<details open={isActive(r)}>
					<summary class="flex cursor-pointer flex-wrap items-center gap-x-2 gap-y-1">
						<Badge variant={variant(r.status)}>{requestStatusLabel[r.status]}</Badge>
						<span>To {requestTarget(r)}</span>
						<span class="text-muted-foreground">
							· asked by {r.requested_by} on {formatDateTime(r.requested_at)}{r.finished_at
								? ` · finished ${formatDateTime(r.finished_at)}`
								: ''}
						</span>
					</summary>
					<!-- The log is text from the updater, shown as text, never as HTML. -->
					<pre class="bg-muted mt-2 max-h-72 overflow-auto rounded p-2 text-xs whitespace-pre-wrap">{r.log ||
							'Nothing logged yet.'}</pre>
				</details>
			</li>
		{/each}
	</ul>
{/if}
