<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import GrantEditor from '#lib/components/app/grant-editor.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { toGrants, toState, type EditorState } from '#lib/roles.js';
	import {
		curlExample,
		dateExpiry,
		dateValue,
		expiryPresets,
		expiryProblem,
		grantableCatalogue,
		maxDateValue,
		presetExpiry,
		tokenNameProblem,
		tokenScopes,
		type NewAPIToken,
		type TokenGrantable
	} from '#lib/tokens.js';
	import { codeReady } from '#lib/totp.js';

	// Makes an API token in two stages. The form takes a name, an expiry, what the token may do (only what you hold
	// yourself), and your password and, with two-factor login on, a code. Once made, the dialog shows the token, once:
	// the server keeps only a hash of it. ondone runs when the dialog closes after a token was made, to refresh the list.
	let {
		open = $bindable(false),
		grantable,
		totpOn,
		ondone
	}: { open: boolean; grantable: TokenGrantable; totpOn: boolean; ondone: () => Promise<void> | void } = $props();

	// $derived recomputes when `grantable` changes (the page reloads it after a change), without an $effect.
	let catalogue = $derived(grantableCatalogue(grantable));

	let name = $state('');
	let expiryChoice = $state<string>('90');
	let customDate = $state('');
	let grants = $state<EditorState>({});
	let password = $state('');
	let code = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let made = $state<NewAPIToken | null>(null);
	let copied = $state(false);
	let copyFailed = $state(false);
	let tried = $state(false); // show field problems only after the first try, not while the form is empty

	// Runs each time the dialog opens (it reads `open`), so it starts empty. Reading `catalogue` here too means the
	// rows match the latest grantable list. $effect.pre, not $effect: it runs before the DOM updates, so the grant
	// picker never renders with rows that aren't there yet (a plain $effect runs after, which is a render too late).
	$effect.pre(() => {
		if (!open) return;
		name = '';
		expiryChoice = '90';
		customDate = '';
		grants = toState([], catalogue);
		password = '';
		code = '';
		error = null;
		made = null;
		copied = false;
		copyFailed = false;
		tried = false;
	});

	let now = $derived(open ? new Date() : new Date(0)); // read again each time the dialog opens
	let expires = $derived(expiryChoice === 'date' ? dateExpiry(customDate) : presetExpiry(Number(expiryChoice), now));
	let nameError = $derived(tokenNameProblem(name));
	let expiryError = $derived(expiryProblem(expires, now));
	let chosen = $derived(toGrants(grants, catalogue));
	let ready = $derived(
		nameError === null && expiryError === null && chosen.length > 0 && password !== '' && (!totpOn || codeReady(code, true))
	);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		tried = true;
		if (!ready || !expires) return;
		busy = true;
		error = null;
		try {
			made = await unwrap(
				api.POST('/api/v1/account/tokens', {
					body: {
						name: name.trim(),
						expires_at: expires.toISOString(),
						grants: chosen,
						password,
						...(totpOn ? { code } : {})
					}
				})
			);
			password = '';
			code = '';
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
			if (e instanceof ApiError && e.code === 'invalid_credentials') password = '';
			if (e instanceof ApiError && (e.code === 'totp_invalid' || e.code === 'invalid_credentials')) code = '';
		} finally {
			busy = false;
		}
	}

	async function copy() {
		if (!made) return;
		copyFailed = false;
		try {
			// The clipboard API needs a secure context (HTTPS or localhost), so it can fail on plain HTTP.
			await navigator.clipboard.writeText(made.token);
			copied = true;
		} catch {
			copyFailed = true;
		}
	}

	// Closing after a token was made refreshes the list. bind:open on the dialog sets `open` to false whichever way it
	// closes (Done, Escape, the X), so this watches for that.
	let wasMade = false;
	$effect(() => {
		if (made) wasMade = true;
		if (!open && wasMade) {
			wasMade = false;
			void ondone();
		}
	});
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
		{#if made}
			<Dialog.Header>
				<Dialog.Title>Your new token</Dialog.Title>
				<Dialog.Description>
					Copy it now and store it where your script or service keeps its secrets. It won't be shown again: if it is
					lost, revoke it and make another.
				</Dialog.Description>
			</Dialog.Header>
			<div class="grid gap-3">
				<!-- The token as plain selectable text, as well as the Copy button, so it can be copied on plain HTTP. -->
				<p class="bg-muted rounded-md p-3 font-mono text-sm break-all select-all" aria-label="Token">{made.token}</p>
				<div class="flex flex-wrap gap-2">
					<Button variant="outline" size="sm" onclick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
				</div>
				{#if copyFailed}
					<p class="text-destructive text-sm">Couldn't copy here (the browser only allows it over HTTPS). Select the token and copy it instead.</p>
				{/if}
				<p class="text-sm">To try it, list the Pi-holes it can reach:</p>
				<pre class="bg-muted overflow-x-auto rounded-md p-3 text-xs"><code>{curlExample(made.token, window.location.origin)}</code></pre>
				<p class="text-muted-foreground text-sm">
					Send it in an <code>Authorization: Bearer</code> header. It works on the Pi-hole and audit log endpoints only,
					and only while you hold what it was given.
				</p>
			</div>
			<Dialog.Footer>
				<Button onclick={() => (open = false)}>Done</Button>
			</Dialog.Footer>
		{:else}
			<Dialog.Header>
				<Dialog.Title>New API token</Dialog.Title>
				<Dialog.Description>
					For a script or integration. It can only do what you tick here, and only while you hold it yourself.
				</Dialog.Description>
			</Dialog.Header>
			<form id="token-create-form" class="grid gap-4" onsubmit={save} novalidate>
				{#if error}
					<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
				{/if}
				<div class="grid gap-1.5">
					<Label for="token-name">Name</Label>
					<Input id="token-name" bind:value={name} maxlength={256} placeholder="Home Assistant" aria-invalid={tried && nameError !== null} />
					{#if tried && nameError}<p class="text-destructive text-sm">{nameError}</p>{/if}
				</div>

				<fieldset class="grid gap-2">
					<legend class="mb-1 text-sm font-medium">Expires</legend>
					<div class="flex flex-wrap items-center gap-x-4 gap-y-2">
						{#each expiryPresets as p (p.days)}
							<label class="flex items-center gap-2 text-sm">
								<input type="radio" name="token-expiry" value={String(p.days)} bind:group={expiryChoice} />
								{p.label}
							</label>
						{/each}
						<label class="flex items-center gap-2 text-sm">
							<input type="radio" name="token-expiry" value="date" bind:group={expiryChoice} />
							On
						</label>
						<Input
							type="date"
							class="w-44"
							bind:value={customDate}
							min={dateValue(now)}
							max={maxDateValue(now)}
							onfocus={() => (expiryChoice = 'date')}
							aria-label="Expiry date"
						/>
					</div>
					{#if expiryError && (tried || expiryChoice === 'date')}
						<p class="text-destructive text-sm">{expiryError}</p>
					{/if}
				</fieldset>

				<div class="grid gap-2">
					<p class="text-sm font-medium">What it can do</p>
					{#if grantable.permissions.length === 0}
						<p class="text-muted-foreground text-sm">You don't hold anything a token can be given.</p>
					{:else}
						<GrantEditor bind:state={grants} {catalogue} scopes={(p) => tokenScopes(grantable, p)} disabled={busy} />
					{/if}
					{#if tried && chosen.length === 0}<p class="text-destructive text-sm">Tick at least one permission.</p>{/if}
				</div>

				<div class="grid gap-1.5">
					<Label for="token-password">Your password</Label>
					<Input id="token-password" type="password" bind:value={password} autocomplete="current-password" />
					{#if tried && password === ''}<p class="text-destructive text-sm">Enter your password.</p>{/if}
				</div>
				{#if totpOn}
					<div class="grid gap-1.5">
						<Label for="token-code">Code from your app, or a recovery code</Label>
						<Input id="token-code" bind:value={code} autocomplete="one-time-code" autocapitalize="off" spellcheck="false" />
						{#if tried && !codeReady(code, true)}
							<p class="text-destructive text-sm">Enter the six-digit code from your app, or a recovery code.</p>
						{/if}
					</div>
				{/if}
			</form>
			<Dialog.Footer>
				<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
				<Button type="submit" form="token-create-form" disabled={busy}>{busy ? 'Making…' : 'Make token'}</Button>
			</Dialog.Footer>
		{/if}
	</Dialog.Content>
</Dialog.Root>
