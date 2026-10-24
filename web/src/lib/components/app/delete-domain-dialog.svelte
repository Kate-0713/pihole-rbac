<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { kindLabel, typeLabel, type Domain } from '#lib/domains.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';

	// AlertDialog rather than Dialog: it is for a question that needs an answer, so it can't be dismissed by clicking
	// outside it, and focus starts on Cancel.
	let {
		open = $bindable(false),
		target,
		targetName,
		entry,
		ondeleted
	}: {
		open: boolean;
		target: string;
		targetName: string;
		entry: Domain | null;
		ondeleted: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);

	async function remove() {
		if (!entry) return;
		busy = true;
		const text = { done: `${entry.domain} deleted`, failed: `Couldn't delete ${entry.domain}` };
		try {
			const { results } = await unwrap(
				api.DELETE('/api/v1/targets/{target}/domains', {
					params: { path: { target } },
					body: { domain: entry.domain, type: entry.type, kind: entry.kind }
				})
			);
			reportResults(results, text);
		} catch (e) {
			reportFailure(e, text);
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
			<AlertDialog.Title>Delete this entry?</AlertDialog.Title>
			<AlertDialog.Description>
				{#if entry}
					<span class="text-foreground font-mono break-all">{entry.domain}</span> comes off the
					{typeLabel[entry.type].toLowerCase()} list ({kindLabel[entry.kind].toLowerCase()}) of {targetName}. Pi-hole
					can't undo this.
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
