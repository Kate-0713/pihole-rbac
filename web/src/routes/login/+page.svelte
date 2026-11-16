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
	import { restartsLogin } from '#lib/totp.js';

	// Component state. Assigning to a $state variable re-renders whatever reads it; bind:value keeps an input and its
	// variable in step both ways.
	let username = $state('');
	let password = $state('');
	let code = $state('');
	// Which form is showing: the password first, then, for someone with two-factor login on, the code.
	let step = $state<'password' | 'code'>('password');
	let error = $state<string | null>(null);
	let busy = $state(false);

	// SvelteKit's goto() stays inside the SPA; replace keeps the login page out of the Back history.
	const enter = () => goto(safeNext(page.url.searchParams.get('next')), { replace: true });

	// Svelte 5 has no on:submit|preventDefault modifier; event handlers are plain props (onsubmit) and call
	// preventDefault themselves.
	async function submit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			const result = await session.login(username, password);
			password = '';
			if (result === 'totp_required') {
				code = '';
				step = 'code';
				return;
			}
			// `page` (from $app/state) is the current URL and route, readable like any other $state.
			await enter();
		} catch (e) {
			password = '';
			// The server's messages are written to be shown: a wrong password and an unknown user get the same one.
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}

	async function submitCode(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			await session.loginTOTP(code);
			code = '';
			await enter();
		} catch (e) {
			code = '';
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
			// Some refusals end the login rather than ask for another code, so the password form comes back.
			if (restartsLogin(e)) step = 'password';
		} finally {
			busy = false;
		}
	}

	function startAgain() {
		code = '';
		error = null;
		step = 'password';
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
			<!-- {#if}/{:else} swaps the two forms. Each is created fresh when shown, so autofocus lands in it. -->
			{#if step === 'password'}
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
			{:else}
				<form class="grid gap-4" onsubmit={submitCode}>
					{#if error}
						<Alert variant="destructive">
							<AlertDescription>{error}</AlertDescription>
						</Alert>
					{/if}
					<div class="grid gap-2">
						<Label for="code">Two-factor code</Label>
						<!-- one-time-code lets a phone or password manager offer the code. Not inputmode="numeric": a
						     recovery code has letters. -->
						<Input id="code" bind:value={code} autocomplete="one-time-code" autocapitalize="off" spellcheck="false" required autofocus />
						<p class="text-muted-foreground text-sm">
							Enter the 6-digit code from your authenticator app, or one of your recovery codes.
						</p>
					</div>
					<Button type="submit" disabled={busy || code.trim() === ''}>
						{busy ? 'Checking…' : 'Verify'}
					</Button>
					<Button type="button" variant="ghost" disabled={busy} onclick={startAgain}>Start again</Button>
				</form>
			{/if}
		</Card.Content>
	</Card.Root>
</main>
