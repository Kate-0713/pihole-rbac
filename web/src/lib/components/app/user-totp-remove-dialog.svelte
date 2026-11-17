<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import type { User } from '#lib/users.js';

	// Removes another user's two-factor login, for someone who has lost both their authenticator and their recovery
	// codes. It logs them out; their next login is by password alone, and goes straight to setting it up again if it is
	// required of them.
	let {
		open = $bindable(false),
		user,
		ondone
	}: { open: boolean; user: User | null; ondone: () => Promise<void> | void } = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		if (open) error = null;
	});

	async function go(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open until the answer is known
		if (!user) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.DELETE('/api/v1/users/{id}/totp', { params: { path: { id: user.id } } }));
			notices.success(`${user.username}'s two-factor login removed.`);
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
			<AlertDialog.Title>Remove {user?.username}'s two-factor login?</AlertDialog.Title>
			<AlertDialog.Description>
				They are logged out at once, and their password alone logs them in until they set it up again.
				{#if user?.totp_required}It's required of them, so they'll be asked to set it up when they next log in.{/if}
				Only do this once you're sure it's them asking.
			</AlertDialog.Description>
		</AlertDialog.Header>
		{#if error}
			<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={go}>
				{busy ? 'Removing…' : 'Remove'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
