<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { toInput, type Channel } from '#lib/notifications.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Asks before disabling or deleting a channel: both stop its notifications, and the channel is told so. A refusal
	// is shown in the dialog, which stays open.
	let {
		open = $bindable(false),
		action,
		channel,
		ondone
	}: { open: boolean; action: 'disable' | 'delete'; channel: Channel | null; ondone: () => Promise<void> | void } = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (open) error = null;
	});

	// A channel that can send, and is enabled, gets a last message saying what happened.
	let told = $derived(channel !== null && channel.enabled && !channel.secret_problem);

	async function confirm(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open until the answer is known
		if (!channel) return;
		busy = true;
		error = null;
		const params = { params: { path: { id: channel.id } } };
		try {
			if (action === 'disable') {
				await unwrap(api.PUT('/api/v1/notifications/channels/{id}', { ...params, body: toInput(channel, { enabled: false }) }));
				notices.success(`${channel.name} disabled.`);
			} else {
				await unwrap(api.DELETE('/api/v1/notifications/channels/{id}', params));
				notices.success(`${channel.name} deleted.`);
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
			<AlertDialog.Title>{action === 'disable' ? 'Disable' : 'Delete'} {channel?.name}?</AlertDialog.Title>
			<AlertDialog.Description>
				{action === 'disable'
					? 'It stops receiving notifications until it is enabled again. Its settings are kept.'
					: 'The channel, its secret and its events are removed.'}
				{told ? ' It gets one last message saying so.' : ''}
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
