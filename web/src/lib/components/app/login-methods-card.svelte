<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { sameMethods, toChoice, toMethods, type Method } from '#lib/ldap.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Which login methods are on, and in which order. Local login is always on: it is the way in when LDAP can't be
	// reached. Turning LDAP on makes the server test a bind first, and a refusal is shown here.
	let {
		methods,
		ldapConfigured,
		onsaved
	}: { methods: Method[]; ldapConfigured: boolean; onsaved: () => Promise<void> | void } = $props();

	// Starts from the saved methods, and starts again whenever they change (after a save, the page reloads them).
	let choice = $state(toChoice([]));
	$effect(() => {
		choice = toChoice(methods);
	});

	let busy = $state(false);
	let error = $state<{ message: string; detail?: string } | null>(null);
	let changed = $derived(!sameMethods(toMethods(choice), methods));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			await unwrap(api.PUT('/api/v1/settings/auth', { body: { methods: toMethods(choice) } }));
			notices.success(choice.ldap ? 'Login methods saved. LDAP login is on.' : 'Login methods saved. LDAP login is off.');
			await onsaved();
		} catch (e) {
			if (e instanceof ApiError) {
				error = { message: e.message, detail: typeof e.details.detail === 'string' ? e.details.detail : undefined };
			} else {
				error = { message: 'Something went wrong. Try again.' };
			}
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Login methods</h2></Card.Title>
		<Card.Description>How people log in. Changes apply at once.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="login-methods-form" class="grid gap-3" onsubmit={save}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>
						<p>{error.message}</p>
						{#if error.detail}<p class="font-mono text-xs break-all">{error.detail}</p>{/if}
					</AlertDescription>
				</Alert>
			{/if}
			<div class="flex items-start gap-2">
				<Checkbox id="method-local" checked disabled class="mt-0.5" aria-describedby="method-local-note" />
				<div class="grid gap-0.5">
					<Label for="method-local" class="font-normal">Local accounts</Label>
					<p id="method-local-note" class="text-muted-foreground text-xs">
						Always on: the way in if LDAP can't be reached.
					</p>
				</div>
			</div>
			<div class="flex items-start gap-2">
				<Checkbox
					id="method-ldap"
					bind:checked={choice.ldap}
					disabled={busy || (!ldapConfigured && !choice.ldap)}
					class="mt-0.5"
					aria-describedby="method-ldap-note"
				/>
				<div class="grid gap-0.5">
					<Label for="method-ldap" class="font-normal">LDAP</Label>
					<p id="method-ldap-note" class="text-muted-foreground text-xs">
						{ldapConfigured
							? 'Turning it on tests a bind with the saved settings first.'
							: 'Save the LDAP server settings below first.'}
					</p>
				</div>
			</div>
			{#if choice.ldap}
				<!-- Native radio buttons: two choices don't need a component. -->
				<fieldset class="grid gap-1.5 pl-6">
					<legend class="text-muted-foreground mb-1 text-xs">Which to try first</legend>
					<label class="flex items-center gap-2 text-sm">
						<input
							type="radio"
							name="method-order"
							value="local"
							checked={!choice.ldapFirst}
							onchange={() => (choice.ldapFirst = false)}
							class="accent-primary"
						/>
						Local accounts, then LDAP
					</label>
					<label class="flex items-center gap-2 text-sm">
						<input
							type="radio"
							name="method-order"
							value="ldap"
							checked={choice.ldapFirst}
							onchange={() => (choice.ldapFirst = true)}
							class="accent-primary"
						/>
						LDAP, then local accounts
					</label>
				</fieldset>
			{/if}
		</form>
	</Card.Content>
	<Card.Footer>
		<Button type="submit" form="login-methods-form" disabled={busy || !changed}>
			{#if busy}{choice.ldap ? 'Testing…' : 'Saving…'}{:else}Save login methods{/if}
		</Button>
	</Card.Footer>
</Card.Root>
