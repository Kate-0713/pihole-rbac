<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { describe, maxReason, reasonProblem, type Row } from '#lib/local-dns.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';

	// Deleting a record or CNAME, named by Pi-hole's own string, with a reason. Every spelling of it is deleted.
	let {
		open = $bindable(false),
		target,
		targetName,
		entry,
		reasonRequired,
		ondeleted
	}: {
		open: boolean;
		target: string;
		targetName: string;
		entry: Row | null;
		reasonRequired: boolean;
		ondeleted: () => Promise<void> | void;
	} = $props();

	let reason = $state('');
	let touched = $state(false);
	let busy = $state(false);
	$effect(() => {
		if (!open) return;
		reason = '';
		touched = false;
	});
	let hint = $derived(reasonProblem(reason, reasonRequired));

	async function remove(event: MouseEvent) {
		// The action would close the dialog at once; it stays open while the reason is missing or the request runs.
		event.preventDefault();
		touched = true;
		if (!entry || hint) return;
		busy = true;
		const shown = describe(entry);
		const text = { done: `${shown} deleted`, failed: `Couldn't delete ${shown}` };
		const why = reason.trim() === '' ? undefined : reason.trim();
		const value = entry.value;
		const send = async (members?: number[]) => {
			const params = { path: { target }, query: members ? { members } : undefined };
			return entry?.kind === 'record'
				? (await unwrap(api.DELETE('/api/v1/targets/{target}/local-dns/records', { params, body: { record: { value }, reason: why } }))).results
				: (await unwrap(api.DELETE('/api/v1/targets/{target}/local-dns/cnames', { params, body: { cname: { value }, reason: why } }))).results;
		};
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
			<AlertDialog.Title>Delete this {entry?.kind === 'cname' ? 'CNAME' : 'record'}?</AlertDialog.Title>
			<AlertDialog.Description>
				{#if entry}
					{targetName} stops answering for
					<span class="text-foreground font-mono break-all">{entry.name}</span>{entry.extra.length > 0
						? ` (and ${entry.extra.join(', ')})`
						: ''}.
					{#if entry.kind === 'cname'}Deleting it restarts DNS on the Pi-hole.{/if}
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<div class="grid gap-2">
			<Label for="local-dns-delete-reason">Reason{reasonRequired ? '' : ' (optional)'}</Label>
			<Input
				id="local-dns-delete-reason"
				bind:value={reason}
				autocomplete="off"
				maxlength={maxReason}
				aria-invalid={touched && hint !== null}
				aria-describedby="local-dns-delete-hint"
				oninput={() => (touched = true)}
			/>
			{#if touched && hint}<p id="local-dns-delete-hint" class="text-destructive text-sm">{hint}</p>{/if}
		</div>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={remove}>
				{busy ? 'Deleting…' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
