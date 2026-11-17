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

	// Turns your own two-factor login off. It asks for your password and a code (or a recovery code), so a session
	// left open somewhere isn't enough. Wrong ones count against the same limits as a failed login.
	let {
		open = $bindable(false),
		required,
		ondone
	}: { open: boolean; required: boolean; ondone: () => Promise<void> | void } = $props();

	let password = $state('');
	let code = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Runs each time the dialog opens (it reads `open`), so it starts empty.
	$effect(() => {
		if (!open) return;
		password = '';
		code = '';
		error = null;
	});

	let ready = $derived(password !== '' && codeReady(code, true));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!ready) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.POST('/api/v1/auth/totp/disable', { body: { password, code } }));
			open = false;
			await ondone();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
			if (e instanceof ApiError && e.code === 'invalid_credentials') password = '';
			code = '';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Turn off two-factor login</Dialog.Title>
			<Dialog.Description>
				{#if required}
					You must use two-factor login, so you'll be asked to set it up again straight away, with a new key. Do this
					to move to a new phone.
				{:else}
					Your password alone will log you in. Your other sessions are logged out.
				{/if}
			</Dialog.Description>
		</Dialog.Header>
		<form id="totp-disable-form" class="grid gap-2" onsubmit={save}>
			{#if error}
				<Alert variant="destructive" class="mb-2"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<Label for="totp-disable-password">Password</Label>
			<Input id="totp-disable-password" type="password" bind:value={password} autocomplete="current-password" />
			<Label for="totp-disable-code" class="mt-2">Code from your app, or a recovery code</Label>
			<Input id="totp-disable-code" bind:value={code} autocomplete="one-time-code" autocapitalize="off" spellcheck="false" />
		</form>
		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="totp-disable-form" variant="destructive" disabled={busy || !ready}>
				{busy ? 'Turning off…' : 'Turn off'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
