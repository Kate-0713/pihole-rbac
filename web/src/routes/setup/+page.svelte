<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { passwordProblem, passwordReady, usernameProblem } from '#lib/password.js';
	import { session } from '#lib/stores/session.svelte.js';

	let token = $state('');
	let username = $state('');
	let password = $state('');
	let confirm = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);

	// $derived values recompute whenever the $state they read changes, so the hints update as the user types.
	let usernameHint = $derived(usernameProblem(username));
	let passwordHint = $derived(passwordProblem(password, confirm));
	let ready = $derived(
		token.trim() !== '' && username.trim() !== '' && usernameHint === null && passwordReady(password, confirm)
	);

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		if (!ready) return;
		busy = true;
		error = null;
		try {
			// The API takes the password once; asking twice is only to catch typos here.
			await session.completeSetup(token.trim(), username.trim(), password);
			await goto('/', { replaceState: true });
		} catch (e) {
			if (e instanceof ApiError && e.code === 'setup_complete') {
				// Someone else (or reset-admin) finished setup meanwhile.
				await goto('/login', { replaceState: true });
				return;
			}
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Set up · pihole-rbac</title>
</svelte:head>

<main class="m-auto w-full max-w-md p-4">
	<Card.Root>
		<Card.Header>
			<Card.Title>Set up pihole-rbac</Card.Title>
			<Card.Description>
				Create the first admin account. You'll need the setup token from the server's log, or run
				<code class="text-foreground">pihole-rbac setup --print-token</code> on the server for a new one.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<form class="grid gap-4" onsubmit={submit}>
				{#if error}
					<Alert variant="destructive">
						<AlertDescription>{error}</AlertDescription>
					</Alert>
				{/if}
				<div class="grid gap-2">
					<Label for="token">Setup token</Label>
					<Input id="token" bind:value={token} autocomplete="off" spellcheck={false} required autofocus />
				</div>
				<div class="grid gap-2">
					<Label for="username">Admin username</Label>
					<Input
						id="username"
						bind:value={username}
						autocomplete="username"
						required
						aria-invalid={usernameHint !== null}
						aria-describedby="username-hint"
					/>
					{#if usernameHint}
						<p id="username-hint" class="text-destructive text-sm">{usernameHint}</p>
					{/if}
				</div>
				<div class="grid gap-2">
					<Label for="password">Password</Label>
					<Input
						id="password"
						type="password"
						bind:value={password}
						autocomplete="new-password"
						required
						aria-invalid={passwordHint !== null}
						aria-describedby="password-hint"
					/>
				</div>
				<div class="grid gap-2">
					<Label for="confirm">Confirm password</Label>
					<Input
						id="confirm"
						type="password"
						bind:value={confirm}
						autocomplete="new-password"
						required
						aria-invalid={confirm !== '' && confirm !== password}
						aria-describedby="password-hint"
					/>
					<p id="password-hint" class={passwordHint ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
						{passwordHint ?? 'At least 12 characters.'}
					</p>
				</div>
				<Button type="submit" disabled={busy || !ready}>{busy ? 'Setting up…' : 'Create admin and log in'}</Button>
			</form>
		</Card.Content>
	</Card.Root>
</main>
