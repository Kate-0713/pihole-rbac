<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { can } from '#lib/permissions.js';
	import { withTarget } from '#lib/stores/targets.svelte.js';

	// Whether a mirrored group's members agreed with the primary on this page's list at the last drift check: shown to
	// anyone who can view the list. It links to the drift page for those who can see it. Nothing is shown before a
	// check has compared the members (drifted undefined).
	let { target, drifted }: { target: string; drifted: boolean | undefined } = $props();

	let href = $derived(can('drift.view', target) ? withTarget('/drift', target) : undefined);
</script>

{#if drifted !== undefined}
	{#if href}
		<a {href} class="rounded-md focus-visible:ring-2 focus-visible:outline-none" title="See what differs">
			<Badge variant={drifted ? 'destructive' : 'secondary'}>{drifted ? 'Drifted' : 'In sync'}</Badge>
		</a>
	{:else}
		<Badge variant={drifted ? 'destructive' : 'secondary'}>{drifted ? 'Drifted' : 'In sync'}</Badge>
	{/if}
{/if}
