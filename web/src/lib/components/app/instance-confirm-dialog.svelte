<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import type { Instance } from '#lib/instances.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Asks before disabling or deleting an instance, since both cut off everyone who uses it. A refusal (an instance
	// still used by a role, say) is shown in the dialog, which stays open.
	let {
		open = $bindable(false),
		action,
		instance,
		ondone
	}: {
		open: boolean;
		action: 'disable' | 'delete';
		instance: Instance | null;
		ondone: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (open) error = null;
	});

	async function confirm(event: MouseEvent) {
		// AlertDialog.Action closes the dialog by default; keep it open until the answer is known.
		event.preventDefault();
		if (!instance) return;
		busy = true;
		error = null;
		const params = { params: { path: { id: instance.id } } };
		try {
			if (action === 'disable') {
				await unwrap(api.POST('/api/v1/instances/{id}/disable', params));
				notices.success(`${instance.name} disabled.`);
			} else {
				await unwrap(api.DELETE('/api/v1/instances/{id}', params));
				notices.success(`${instance.name} deleted.`);
			}
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
			<AlertDialog.Title>{action === 'disable' ? 'Disable' : 'Delete'} {instance?.name}?</AlertDialog.Title>
			<AlertDialog.Description>
				{#if action === 'disable'}
					Nobody can use this Pi-hole through pihole-rbac until it is enabled again. Its settings and the
					permissions on it are kept.
				{:else}
					The instance and its settings are removed from pihole-rbac. Nothing changes on the Pi-hole itself. An
					instance that roles or groups still refer to can't be deleted.
				{/if}
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
				{#if busy}{action === 'disable' ? 'Disabling…' : 'Deleting…'}{:else}{action === 'disable' ? 'Disable' : 'Delete'}{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
