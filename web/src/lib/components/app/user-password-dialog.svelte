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
	import type { User } from '#lib/users.js';

	// Sets another local user's password without their current one, for someone who has forgotten theirs. Their
	// sessions end. Your own password is changed from the account menu instead, which asks for the current one.
	let { open = $bindable(false), user }: { open: boolean; user: User | null } = $props();

	let password = $state('');
	let passwordAgain = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	$effect(() => {
		if (!open) return;
		password = '';
		passwordAgain = '';
		error = null;
		touched = false;
	});

	let hint = $derived(passwordProblem(password, passwordAgain));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!user || !passwordReady(password, passwordAgain)) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.POST('/api/v1/users/{id}/password', { params: { path: { id: user.id } }, body: { password } }));
			notices.success(`New password set for ${user.username}.`);
			open = false;
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
			<Dialog.Title>Set a password for {user?.username}</Dialog.Title>
			<Dialog.Description>
				{user?.username} is logged out everywhere and logs in with the new password.
			</Dialog.Description>
		</Dialog.Header>

		<form id="user-password-form" class="grid gap-2" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive" class="mb-2">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}
			<Label for="set-user-password">New password</Label>
			<Input
				id="set-user-password"
				type="password"
				bind:value={password}
				autocomplete="new-password"
				aria-invalid={touched && hint !== null}
				aria-describedby="set-user-password-hint"
			/>
			<Label for="set-user-password-again" class="mt-2">New password again</Label>
			<Input
				id="set-user-password-again"
				type="password"
				bind:value={passwordAgain}
				autocomplete="new-password"
				aria-invalid={touched && hint !== null}
				aria-describedby="set-user-password-hint"
			/>
			<p
				id="set-user-password-hint"
				class="text-sm"
				class:text-destructive={touched && hint}
				class:text-muted-foreground={!(touched && hint)}
			>
				{touched && hint ? hint : 'At least 12 characters.'}
			</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="user-password-form" disabled={busy || (touched && hint !== null)}>
				{busy ? 'Saving…' : 'Set password'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
