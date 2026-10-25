<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import type { Group } from '#lib/groups.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Asks before deleting a group. A refusal (a group a role still grants on, say) is shown in the dialog, which stays
	// open.
	let {
		open = $bindable(false),
		group,
		ondone
	}: { open: boolean; group: Group | null; ondone: () => Promise<void> | void } = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (open) error = null;
	});

	async function confirm(event: MouseEvent) {
		// AlertDialog.Action closes the dialog by default; keep it open until the answer is known.
		event.preventDefault();
		if (!group) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.DELETE('/api/v1/instance-groups/{id}', { params: { path: { id: group.id } } }));
			notices.success(`${group.name} deleted.`);
			open = false;
			await ondone();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Delete {group?.name}?</AlertDialog.Title>
			<AlertDialog.Description>
				The group is removed; its instances stay as they are, and nothing changes on any Pi-hole. A group that roles
				or client reset still refer to can't be deleted.
			</AlertDialog.Description>
		</AlertDialog.Header>
		{#if error}
			<Alert variant="destructive">
				<AlertDescription>{error}</AlertDescription>
			</Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={confirm}>
				{busy ? 'Deleting…' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
