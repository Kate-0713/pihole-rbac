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
	import { passwordProblem, passwordReady } from '#lib/password.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Changes the logged-in user's own password, from the account menu. Local accounts only: an LDAP password lives in
	// the directory. A wrong current password counts against the same limits as a failed login.
	let { open = $bindable(false) }: { open: boolean } = $props();

	let current = $state('');
	let password = $state('');
	let passwordAgain = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	$effect(() => {
		if (!open) return;
		current = '';
		password = '';
		passwordAgain = '';
		error = null;
		touched = false;
	});

	let hint = $derived(
		password !== '' && password === current
			? 'Choose a password different from the current one.'
			: passwordProblem(password, passwordAgain)
	);
	let ready = $derived(current !== '' && hint === null && passwordReady(password, passwordAgain));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.POST('/api/v1/auth/password', { body: { current_password: current, new_password: password } }));
			notices.success('Password changed. Your other sessions have been logged out.');
			open = false;
		} catch (e) {
			// invalid_credentials is a 401 too, but its code isn't unauthenticated, so it doesn't log the user out.
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
			if (e instanceof ApiError && e.code === 'invalid_credentials') current = '';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Change your password</Dialog.Title>
			<Dialog.Description>Your other sessions are logged out; this one stays.</Dialog.Description>
		</Dialog.Header>

		<form id="change-password-form" class="grid gap-2" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive" class="mb-2">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}
			<Label for="current-password">Current password</Label>
			<Input
				id="current-password"
				type="password"
				bind:value={current}
				autocomplete="current-password"
				aria-invalid={touched && current === ''}
				aria-describedby="current-password-hint"
			/>
			{#if touched && current === ''}
				<p id="current-password-hint" class="text-destructive text-sm">Enter your current password.</p>
			{/if}
			<Label for="new-password" class="mt-2">New password</Label>
			<Input
				id="new-password"
				type="password"
				bind:value={password}
				autocomplete="new-password"
				aria-invalid={touched && hint !== null}
				aria-describedby="new-password-hint"
			/>
			<Label for="new-password-again" class="mt-2">New password again</Label>
			<Input
				id="new-password-again"
				type="password"
				bind:value={passwordAgain}
				autocomplete="new-password"
				aria-invalid={touched && hint !== null}
				aria-describedby="new-password-hint"
			/>
			<p
				id="new-password-hint"
				class="text-sm"
				class:text-destructive={touched && hint}
				class:text-muted-foreground={!(touched && hint)}
			>
				{touched && hint ? hint : 'At least 12 characters.'}
			</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="change-password-form" disabled={busy || (touched && !ready)}>
				{busy ? 'Changing…' : 'Change password'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
