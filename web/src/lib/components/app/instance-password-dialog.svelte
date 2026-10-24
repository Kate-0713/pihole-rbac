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
	import { passwordProblem, type Instance } from '#lib/instances.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Stores a new app password for an instance, as when the Pi-hole's password is rotated. For an enabled instance the
	// server tries it first, so a typo can't cut the instance off; a refusal stays in the dialog.
	let {
		open = $bindable(false),
		instance,
		onsaved
	}: {
		open: boolean;
		instance: Instance | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let password = $state('');
	let passwordAgain = $state('');
	let error = $state<{ message: string; detail?: string } | null>(null);
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
		if (!instance || hint !== null) return;
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/instances/{id}/password', { params: { path: { id: instance.id } }, body: { password } })
			);
			notices.success(`New password stored for ${instance.name}.`);
			open = false;
			await onsaved();
		} catch (e) {
			if (e instanceof ApiError) {
				const detail = typeof e.details.detail === 'string' ? e.details.detail : undefined;
				error = { message: e.message, detail };
			} else {
				error = { message: 'Something went wrong. Try again.' };
			}
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Change the password of {instance?.name}</Dialog.Title>
			<Dialog.Description>
				{#if instance?.enabled}
					The new password is tried on the Pi-hole first, and only stored if it works.
				{:else}
					The instance is disabled, so the password is stored without trying it. It is tried when the instance is
					enabled.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="instance-password-form" class="grid gap-2" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive" class="mb-2">
					<AlertDescription>
						<p>{error.message}</p>
						{#if error.detail}<p class="font-mono text-xs break-all">{error.detail}</p>{/if}
					</AlertDescription>
				</Alert>
			{/if}
			<Label for="new-instance-password">New app password</Label>
			<Input
				id="new-instance-password"
				type="password"
				bind:value={password}
				autocomplete="new-password"
				aria-invalid={touched && hint !== null}
				aria-describedby="new-instance-password-hint"
			/>
			<Label for="new-instance-password-again" class="mt-2">New app password again</Label>
			<Input
				id="new-instance-password-again"
				type="password"
				bind:value={passwordAgain}
				autocomplete="new-password"
				aria-invalid={touched && hint !== null}
				aria-describedby="new-instance-password-hint"
			/>
			{#if touched && hint}
				<p id="new-instance-password-hint" class="text-destructive text-sm">{hint}</p>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="instance-password-form" disabled={busy || (touched && hint !== null)}>
				{#if busy}{instance?.enabled ? 'Trying…' : 'Saving…'}{:else}Store password{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
