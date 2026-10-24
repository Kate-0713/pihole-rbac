<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap, type Schemas } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { commentProblem, type PiholeGroup } from '#lib/pihole.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';
	import GroupPicker from './group-picker.svelte';

	type PiholeClient = Schemas['PiholeClient'];

	// Changes a client's groups and comment. Clients are only changed here, never added or removed: clients.edit is
	// for moving clients between groups, and the server refuses to create one.
	let {
		open = $bindable(false),
		target,
		targetName,
		groups,
		client,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		groups: PiholeGroup[];
		client: PiholeClient | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let comment = $state('');
	let selected = $state<number[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Filled each time the dialog opens; it reads open, client and nothing it sets, so typing doesn't reset it.
	$effect(() => {
		if (!open || !client) return;
		comment = client.comment;
		selected = [...client.groups];
		error = null;
	});

	let commentHint = $derived(commentProblem(comment));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!client || commentHint) return;
		busy = true;
		error = null;
		try {
			const { results } = await unwrap(
				api.PATCH('/api/v1/targets/{target}/clients', {
					params: { path: { target } },
					body: { client: client.client, comment, groups: selected }
				})
			);
			reportResults(results, { done: `${client.client} updated`, failed: `Couldn't update ${client.client}` });
			open = false;
			await onsaved();
		} catch (e) {
			error = failureMessage(e);
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>Change client</Dialog.Title>
			<Dialog.Description>
				{#if client}
					<span class="font-mono break-all">{client.client}</span>{#if client.name}&nbsp;({client.name}){/if} on {targetName}.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="client-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}
			<div class="grid gap-2">
				<Label for="client-comment">Comment</Label>
				<Input
					id="client-comment"
					bind:value={comment}
					autocomplete="off"
					aria-invalid={commentHint !== null}
					aria-describedby="client-comment-hint"
				/>
				{#if commentHint}
					<p id="client-comment-hint" class="text-destructive text-sm">{commentHint}</p>
				{/if}
			</div>
			<GroupPicker {groups} bind:selected idPrefix="client" disabled={busy} />
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="client-form" disabled={busy || commentHint !== null}>
				{busy ? 'Saving…' : 'Save'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
