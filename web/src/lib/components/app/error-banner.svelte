<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import XIcon from '@lucide/svelte/icons/x';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
</script>

<!-- Failures stay until dismissed, newest first. Messages are shown as text, never as HTML. -->
{#if notices.errors.length > 0}
	<div class="grid gap-2" aria-live="polite">
		{#each notices.errors as n (n.id)}
			<Alert variant="destructive" class="pr-12">
				<AlertDescription>{n.message}</AlertDescription>
				<Button
					variant="ghost"
					size="icon-sm"
					class="absolute top-1.5 right-1.5"
					aria-label="Dismiss"
					onclick={() => notices.dismiss(n.id)}
				>
					<XIcon />
				</Button>
			</Alert>
		{/each}
	</div>
{/if}
