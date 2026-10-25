<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { page } from '$app/state';
	import { Alert, AlertDescription, AlertTitle } from '#lib/components/ui/alert/index.js';
	import { targets, withTarget, type Target } from '#lib/stores/targets.svelte.js';

	// Shown above a page that can change one member of a mirrored group on its own: such a change goes to that
	// instance alone, so it will differ from the group until the group is reconciled. The server allows it (and flags
	// it in the audit log); this is the warning before it happens. When the user can act on the group itself, the
	// note links to the same page for the group.
	let { target }: { target: Target } = $props();

	let group = $derived(target.mirrored_group);
	let groupTarget = $derived(group ? targets.find(group.id) : undefined);
</script>

{#if group}
	<Alert>
		<AlertTitle>{target.name} is a member of the mirrored group {group.name}</AlertTitle>
		<AlertDescription>
			<p>
				Changes made here go to {target.name} alone, so it will differ from the group's other members until the group
				is reconciled.
				{#if groupTarget}
					To change every member, <a class="underline underline-offset-4" href={withTarget(page.url.pathname, group.id)}
						>work on {group.name}</a
					> instead.
				{/if}
			</p>
		</AlertDescription>
	</Alert>
{/if}
