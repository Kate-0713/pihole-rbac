<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { secretProblem, secretWord, type Channel } from '#lib/notifications.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Stores a new webhook URL or access token for a channel, as when a webhook is replaced or a token rotated. It is
	// pasted, not typed, so it is asked for once; Send test then shows whether it works. The old destination is told.
	let {
		open = $bindable(false),
		channel,
		onsaved
	}: { open: boolean; channel: Channel | null; onsaved: () => Promise<void> | void } = $props();

	let secret = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	$effect(() => {
		if (!open) return;
		secret = '';
		error = null;
		touched = false;
	});

	let word = $derived(channel ? secretWord(channel.kind) : 'secret');
	let hint = $derived(channel ? secretProblem(channel.kind, secret.trim()) : null);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!channel || hint !== null) return;
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/notifications/channels/{id}/secret', { params: { path: { id: channel.id } }, body: { secret: secret.trim() } })
			);
			notices.success(`New ${word} stored for ${channel.name}.`);
			open = false;
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Replace the {word} of {channel?.name}</Dialog.Title>
			<Dialog.Description>
				{channel?.secret_source === 'none'
					? `The channel can send once it has a ${word}.`
					: `The current destination is told that it was replaced.`}
			</Dialog.Description>
		</Dialog.Header>
		<form id="channel-secret-form" class="grid gap-2" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive" class="mb-2"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<Label for="new-channel-secret">New {word}</Label>
			<Input
				id="new-channel-secret"
				type="password"
				bind:value={secret}
				autocomplete="off"
				spellcheck={false}
				aria-invalid={touched && hint !== null}
				aria-describedby="new-channel-secret-hint"
			/>
			{#if touched && hint}
				<p id="new-channel-secret-hint" class="text-destructive text-sm">{hint}</p>
			{/if}
		</form>
		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="channel-secret-form" disabled={busy || (touched && hint !== null)}>
				{busy ? 'Saving…' : `Store ${word}`}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
