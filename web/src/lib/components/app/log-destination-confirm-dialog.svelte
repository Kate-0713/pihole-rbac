<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { toInput, type LogDestination } from '#lib/logdestinations.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Asks before disabling or deleting a destination: both stop the log reaching it, and the place it was sending to
	// is told so. A refusal is shown in the dialog, which stays open.
	let {
		open = $bindable(false),
		action,
		destination,
		ondone
	}: {
		open: boolean;
		action: 'disable' | 'delete';
		destination: LogDestination | null;
		ondone: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (open) error = null;
	});

	async function confirm(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open until the answer is known
		if (!destination) return;
		busy = true;
		error = null;
		const params = { params: { path: { id: destination.id } } };
		try {
			if (action === 'disable') {
				await unwrap(api.PUT('/api/v1/settings/log-destinations/{id}', { ...params, body: toInput(destination, { enabled: false }) }));
				notices.success(`${destination.name} disabled.`);
			} else {
				await unwrap(api.DELETE('/api/v1/settings/log-destinations/{id}', params));
				notices.success(`${destination.name} deleted.`);
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
			<AlertDialog.Title>{action === 'disable' ? 'Disable' : 'Delete'} {destination?.name}?</AlertDialog.Title>
			<AlertDialog.Description>
				{action === 'disable'
					? 'The log stops going to it until it is enabled again. Its settings are kept, and what it missed is sent then.'
					: 'The destination is removed, and the log stops going to it.'}
				{destination?.enabled ? ' It is first sent what it hadn’t had, up to this change, so it hears about it.' : ''}
			</AlertDialog.Description>
		</AlertDialog.Header>
		{#if error}
			<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={confirm}>
				{#if busy}{action === 'disable' ? 'Disabling…' : 'Deleting…'}{:else}{action === 'disable' ? 'Disable' : 'Delete'}{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
