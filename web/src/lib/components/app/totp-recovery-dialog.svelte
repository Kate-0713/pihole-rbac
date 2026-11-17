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
	import { codeReady } from '#lib/totp.js';
	import RecoveryCodes from './recovery-codes.svelte';

	// Replaces your recovery codes with ten new ones, given a code from your app or one of the current recovery codes.
	// The new codes are shown in the dialog, once.
	let { open = $bindable(false), ondone }: { open: boolean; ondone: () => Promise<void> | void } = $props();

	let code = $state('');
	let codes = $state<string[] | null>(null);
	let error = $state<string | null>(null);
	let busy = $state(false);

	$effect(() => {
		if (!open) return;
		code = '';
		codes = null;
		error = null;
	});

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!codeReady(code, true)) return;
		busy = true;
		error = null;
		try {
			codes = (await unwrap(api.POST('/api/v1/auth/totp/recovery-codes', { body: { code } }))).recovery_codes;
			await ondone();
		} catch (e) {
			code = '';
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>New recovery codes</Dialog.Title>
			<Dialog.Description>
				{codes ? 'Your old recovery codes no longer work.' : 'Your old recovery codes stop working when you get new ones.'}
			</Dialog.Description>
		</Dialog.Header>
		{#if codes}
			<RecoveryCodes {codes} />
			<Dialog.Footer>
				<Button onclick={() => (open = false)}>Done</Button>
			</Dialog.Footer>
		{:else}
			<form id="totp-recovery-form" class="grid gap-2" onsubmit={save}>
				{#if error}
					<Alert variant="destructive" class="mb-2"><AlertDescription>{error}</AlertDescription></Alert>
				{/if}
				<Label for="totp-recovery-code">Code from your app, or a recovery code</Label>
				<Input id="totp-recovery-code" bind:value={code} autocomplete="one-time-code" autocapitalize="off" spellcheck="false" />
			</form>
			<Dialog.Footer>
				<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
				<Button type="submit" form="totp-recovery-form" disabled={busy || !codeReady(code, true)}>
					{busy ? 'Getting codes…' : 'Get new codes'}
				</Button>
			</Dialog.Footer>
		{/if}
	</Dialog.Content>
</Dialog.Root>
