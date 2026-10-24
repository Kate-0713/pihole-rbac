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
	import { passwordProblem, passwordReady, usernameProblem } from '#lib/password.js';
	import type { Role } from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import RoleChecklist from './role-checklist.svelte';

	// Creates a local user with a password and roles. LDAP users aren't created here: they get an account when they
	// first log in.
	let {
		open = $bindable(false),
		roles,
		onsaved
	}: { open: boolean; roles: Role[]; onsaved: () => Promise<void> | void } = $props();

	let username = $state('');
	let password = $state('');
	let passwordAgain = $state('');
	let selected = $state<number[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	// $effect runs after the component renders and again whenever what it reads changes; here, each time the dialog
	// opens, so it starts empty rather than showing the last user's details.
	$effect(() => {
		if (!open) return;
		username = '';
		password = '';
		passwordAgain = '';
		selected = [];
		error = null;
		touched = false;
	});

	let hints = $derived({
		username: username.trim() === '' ? 'Enter a username.' : usernameProblem(username),
		password: passwordProblem(password, passwordAgain)
	});
	let ready = $derived(hints.username === null && passwordReady(password, passwordAgain));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		try {
			const created = await unwrap(
				api.POST('/api/v1/users', { body: { username: username.trim(), password, role_ids: selected } })
			);
			notices.success(`User ${created.username} created.`);
			open = false;
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>New user</Dialog.Title>
			<Dialog.Description>
				A local account, with a password stored in pihole-rbac. LDAP users get an account when they first log in.
			</Dialog.Description>
		</Dialog.Header>

		<form id="user-create-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}
			<div class="grid gap-2">
				<Label for="new-username">Username</Label>
				<Input
					id="new-username"
					bind:value={username}
					autocomplete="off"
					autocapitalize="none"
					spellcheck={false}
					aria-invalid={touched && hints.username !== null}
					aria-describedby="new-username-hint"
				/>
				{#if touched && hints.username}
					<p id="new-username-hint" class="text-destructive text-sm">{hints.username}</p>
				{/if}
			</div>
			<div class="grid gap-2">
				<Label for="new-user-password">Password</Label>
				<Input
					id="new-user-password"
					type="password"
					bind:value={password}
					autocomplete="new-password"
					aria-invalid={touched && hints.password !== null}
					aria-describedby="new-user-password-hint"
				/>
				<Label for="new-user-password-again" class="mt-2">Password again</Label>
				<Input
					id="new-user-password-again"
					type="password"
					bind:value={passwordAgain}
					autocomplete="new-password"
					aria-invalid={touched && hints.password !== null}
					aria-describedby="new-user-password-hint"
				/>
				<p
					id="new-user-password-hint"
					class="text-sm"
					class:text-destructive={touched && hints.password}
					class:text-muted-foreground={!(touched && hints.password)}
				>
					{touched && hints.password ? hints.password : 'At least 12 characters.'}
				</p>
			</div>
			<RoleChecklist bind:selected {roles} />
			{#if selected.length === 0}
				<p class="text-muted-foreground text-sm">Without a role, the user can't log in.</p>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="user-create-form" disabled={busy || (touched && !ready)}>
				{busy ? 'Creating…' : 'Create user'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
