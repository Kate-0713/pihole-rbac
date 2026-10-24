<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';

	// Asks before a change the server answered with 409 confirmation_required: one that would take away the user's own
	// roles.manage or users.manage, or disable or delete their own account. `message` is the server's, which says
	// exactly what would be lost. Confirming calls onconfirm, which repeats the request with ?confirm=true.
	let {
		open = $bindable(false),
		message,
		lose,
		onconfirm
	}: {
		open: boolean;
		message: string;
		lose: string[];
		onconfirm: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);

	async function confirm(event: MouseEvent) {
		// AlertDialog.Action closes the dialog by default; keep it open while the request runs.
		event.preventDefault();
		busy = true;
		try {
			await onconfirm();
		} finally {
			busy = false;
			open = false;
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>
				{lose.includes('account') ? 'Change your own account?' : 'Remove your own access?'}
			</AlertDialog.Title>
			<AlertDialog.Description>{message}</AlertDialog.Description>
		</AlertDialog.Header>
		{#if lose.length > 0 && !lose.includes('account')}
			<p class="text-sm">
				You would lose: {#each lose as p, i (p)}<code>{p}</code>{i < lose.length - 1 ? ', ' : ''}{/each}. Only someone
				who still holds it can give it back.
			</p>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={confirm}>
				{busy ? 'Saving…' : 'Go ahead'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
