<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ApiError } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { safeNext, session } from '#lib/stores/session.svelte.js';

	// Component state. Assigning to a $state variable re-renders whatever reads it; bind:value keeps an input and its
	// variable in step both ways.
	let username = $state('');
	let password = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Svelte 5 has no on:submit|preventDefault modifier; event handlers are plain props (onsubmit) and call
	// preventDefault themselves.
	async function submit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			await session.login(username, password);
			password = '';
			// `page` (from $app/state) is the current URL and route, readable like any other $state.
			await goto(safeNext(page.url.searchParams.get('next')), { replace: true });
		} catch (e) {
			password = '';
			// The server's messages are written to be shown: a wrong password and an unknown user get the same one.
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Log in · pihole-rbac</title>
</svelte:head>

<main class="m-auto w-full max-w-sm p-4">
	<Card.Root>
		<Card.Header>
			<Card.Title>Log in to pihole-rbac</Card.Title>
		</Card.Header>
		<Card.Content>
			<form class="grid gap-4" onsubmit={submit}>
				{#if error}
					<Alert variant="destructive">
						<AlertDescription>{error}</AlertDescription>
					</Alert>
				{/if}
				<div class="grid gap-2">
					<Label for="username">Username</Label>
					<Input id="username" bind:value={username} autocomplete="username" required autofocus />
				</div>
				<div class="grid gap-2">
					<Label for="password">Password</Label>
					<Input id="password" type="password" bind:value={password} autocomplete="current-password" required />
				</div>
				<Button type="submit" disabled={busy || username.trim() === '' || password === ''}>
					{busy ? 'Logging in…' : 'Log in'}
				</Button>
			</form>
		</Card.Content>
	</Card.Root>
</main>
