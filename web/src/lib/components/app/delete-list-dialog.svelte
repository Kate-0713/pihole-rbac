<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { typeLabel, type PiholeList } from '#lib/lists.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';

	let {
		open = $bindable(false),
		target,
		targetName,
		list,
		ondeleted
	}: {
		open: boolean;
		target: string;
		targetName: string;
		list: PiholeList | null;
		ondeleted: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);

	async function remove() {
		if (!list) return;
		busy = true;
		const text = { done: `${list.address} deleted`, failed: `Couldn't delete ${list.address}` };
		const body = { address: list.address, type: list.type };
		const send = async (members?: number[]) =>
			(
				await unwrap(
					api.DELETE('/api/v1/targets/{target}/lists', {
						params: { path: { target }, query: members ? { members } : undefined },
						body
					})
				)
			).results;
		const retry = { retry: send, after: ondeleted };
		try {
			reportResults(await send(), text, retry);
		} catch (e) {
			reportFailure(e, text, retry);
		} finally {
			busy = false;
			open = false;
			await ondeleted();
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Delete this list?</AlertDialog.Title>
			<AlertDialog.Description>
				{#if list}
					{targetName} stops subscribing to the {typeLabel[list.type].toLowerCase()}
					<span class="text-foreground font-mono break-all">{list.address}</span>. Its domains stop applying at once.
					Pi-hole can't undo this.
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={remove}>
				{busy ? 'Deleting…' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
