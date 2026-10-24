<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { needsConfirmation } from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { confirmText, type User } from '#lib/users.js';

	// Asks before disabling or deleting a user. For your own account the server answers confirmation_required; the
	// dialog then shows its message and the button repeats the request with ?confirm=true. A refusal (the last
	// enabled local admin, say) is shown in the dialog, which stays open.
	let {
		open = $bindable(false),
		action,
		user,
		self,
		ondone
	}: {
		open: boolean;
		action: 'disable' | 'delete';
		user: User | null;
		self: boolean;
		ondone: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);
	let confirmMessage = $state<string | null>(null);

	$effect(() => {
		if (!open) return;
		error = null;
		confirmMessage = null;
	});

	let verb = $derived(action === 'disable' ? 'Disable' : 'Delete');

	async function go(event: MouseEvent) {
		event.preventDefault(); // AlertDialog.Action would close the dialog; keep it open until the answer is known
		if (!user) return;
		busy = true;
		error = null;
		const params = { path: { id: user.id }, query: confirmMessage !== null ? { confirm: true } : {} };
		try {
			if (action === 'disable') {
				await unwrap(api.POST('/api/v1/users/{id}/disable', { params }));
			} else {
				await unwrap(api.DELETE('/api/v1/users/{id}', { params }));
			}
			notices.success(`${user.username} ${action === 'disable' ? 'disabled' : 'deleted'}.`);
			open = false;
			await ondone();
		} catch (e) {
			if (needsConfirmation(e)) confirmMessage = e.message;
			else error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>{verb} {self ? 'your own account' : user?.username}?</AlertDialog.Title>
			<AlertDialog.Description>{user ? confirmText(action, user, self) : ''}</AlertDialog.Description>
		</AlertDialog.Header>
		{#if confirmMessage}
			<Alert variant="destructive">
				<AlertDescription>{confirmMessage}</AlertDescription>
			</Alert>
		{/if}
		{#if error}
			<Alert variant="destructive">
				<AlertDescription>{error}</AlertDescription>
			</Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={go}>
				{#if busy}Working…{:else if confirmMessage}Yes, {action} my account{:else}{verb}{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
