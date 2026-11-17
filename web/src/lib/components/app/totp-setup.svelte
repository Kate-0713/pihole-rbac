<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { codeReady, groupSecret, type TOTPEnrolment } from '#lib/totp.js';

	// Setting up two-factor login: ask the server for a secret, show it as a QR code and as text, and turn it on once
	// a code from the authenticator app proves the app has it. onenabled gets the recovery codes, which the server
	// returns once.
	let { onenabled }: { onenabled: (codes: string[]) => Promise<void> | void } = $props();

	let enrolment = $state<TOTPEnrolment | null>(null);
	let code = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);

	async function start() {
		busy = true;
		error = null;
		try {
			// Asking again replaces a secret that was never confirmed, so starting over is always safe.
			enrolment = await unwrap(api.POST('/api/v1/auth/totp/setup'));
			code = '';
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}

	async function confirm(event: SubmitEvent) {
		event.preventDefault();
		if (!codeReady(code, false)) return;
		busy = true;
		error = null;
		try {
			const { recovery_codes } = await unwrap(api.POST('/api/v1/auth/totp/confirm', { body: { code } }));
			enrolment = null;
			await onenabled(recovery_codes);
		} catch (e) {
			code = '';
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

{#if error}
	<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
{/if}

{#if !enrolment}
	<Button class="w-fit" disabled={busy} onclick={start}>{busy ? 'Starting…' : 'Set up two-factor login'}</Button>
{:else}
	<ol class="grid list-decimal gap-4 pl-5 text-sm">
		<li class="grid gap-2">
			<span>Scan this with an authenticator app (Aegis, Google Authenticator, 1Password, Bitwarden and the like).</span>
			<!-- A data: URI the server made: an image can't run script, and the CSP allows data: images. -->
			<img src={enrolment.qr} alt="QR code for your authenticator app" class="size-48 rounded-md bg-white p-1" />
		</li>
		<li class="grid gap-1">
			<span>Or, if the app can't scan it, type in this key:</span>
			<code class="bg-muted w-fit rounded px-2 py-1 font-mono break-all" aria-label="Secret key">
				{groupSecret(enrolment.secret)}
			</code>
		</li>
		<li>
			<form class="grid gap-2" onsubmit={confirm}>
				<Label for="totp-confirm-code">Enter the 6-digit code the app shows</Label>
				<div class="flex flex-wrap gap-2">
					<Input
						id="totp-confirm-code"
						class="w-40"
						bind:value={code}
						inputmode="numeric"
						autocomplete="one-time-code"
						autofocus
					/>
					<Button type="submit" disabled={busy || !codeReady(code, false)}>{busy ? 'Checking…' : 'Turn on'}</Button>
					<Button type="button" variant="ghost" disabled={busy} onclick={start}>New key</Button>
				</div>
			</form>
		</li>
	</ol>
{/if}
