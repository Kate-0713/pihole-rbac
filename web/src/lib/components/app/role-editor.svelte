<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import {
		descriptionProblem,
		needsConfirmation,
		roleNameProblem,
		sameGrants,
		toGrants,
		toState,
		wouldLose,
		type Catalogue,
		type Role
	} from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import ConfirmChangeDialog from './confirm-change-dialog.svelte';
	import GrantEditor from './grant-editor.svelte';

	// Creates a role (role = null) or changes one: its name, description and grants. A role the user can't change
	// (the builtin admin role, or one holding grants they don't) is shown read-only with the reason.
	let { role, catalogue }: { role: Role | null; catalogue: Catalogue } = $props();

	// The form copies the role's values once, then holds the user's edits until they save. Svelte warns when $state
	// starts from a prop, because a later change to the prop wouldn't reach it; that is intended here. Each role page
	// gets its own instance of this component, so `role` never changes underneath the form.
	// svelte-ignore state_referenced_locally
	let name = $state(role?.name ?? '');
	// svelte-ignore state_referenced_locally
	let description = $state(role?.description ?? '');
	// svelte-ignore state_referenced_locally
	let grants = $state(toState(role?.grants ?? [], catalogue));

	let busy = $state(false);
	let error = $state<string | null>(null);
	let touched = $state(false);
	let confirmOpen = $state(false);
	let confirmMessage = $state('');
	let confirmLose = $state<string[]>([]);

	let readonlyReason = $derived(
		role?.builtin
			? "The builtin admin role always holds every permission, and can't be changed."
			: role && !role.manageable
				? "This role holds permissions you don't, so you can't change it."
				: null
	);
	let hints = $derived({ name: roleNameProblem(name), description: descriptionProblem(description) });
	let ready = $derived(hints.name === null && hints.description === null);
	let newGrants = $derived(toGrants(grants, catalogue));
	let grantsChanged = $derived(!role || !sameGrants(role.grants, newGrants));
	let detailsChanged = $derived(!role || name.trim() !== role.name || description.trim() !== role.description);

	async function finish(message: string) {
		notices.success(message);
		// The user's own permissions may have changed (if they hold this role), so the nav follows at once.
		await Promise.allSettled([session.refresh(), targets.refresh()]);
		await goto('/admin/roles');
	}

	async function saveGrants(id: number, confirm: boolean) {
		await unwrap(
			api.PUT('/api/v1/roles/{id}/grants', {
				params: { path: { id }, query: confirm ? { confirm: true } : {} },
				body: { grants: newGrants }
			})
		);
	}

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready || readonlyReason) return;
		busy = true;
		error = null;
		try {
			if (!role) {
				const created = await unwrap(
					api.POST('/api/v1/roles', {
						body: { name: name.trim(), description: description.trim(), grants: newGrants }
					})
				);
				await finish(`Role ${created.name} created.`);
				return;
			}
			// Grants first: they are the change that may need confirming, so if it is cancelled nothing is saved.
			if (grantsChanged) {
				try {
					await saveGrants(role.id, false);
				} catch (e) {
					if (!needsConfirmation(e)) throw e;
					confirmMessage = e.message;
					confirmLose = wouldLose(e);
					confirmOpen = true;
					return; // the dialog carries on with confirmed()
				}
			}
			await saveDetails();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}

	async function saveDetails() {
		if (!role) return;
		if (detailsChanged) {
			await unwrap(
				api.PUT('/api/v1/roles/{id}', {
					params: { path: { id: role.id } },
					body: { name: name.trim(), description: description.trim() }
				})
			);
		}
		await finish(`Role ${name.trim()} saved.`);
	}

	async function confirmed() {
		if (!role) return;
		try {
			await saveGrants(role.id, true);
			await saveDetails();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		}
	}
</script>

<form class="grid gap-6" onsubmit={save} oninput={() => (touched = true)}>
	{#if readonlyReason}
		<Alert>
			<AlertDescription>{readonlyReason}</AlertDescription>
		</Alert>
	{/if}
	{#if error}
		<Alert variant="destructive">
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}

	<div class="grid max-w-xl gap-4">
		<div class="grid gap-2">
			<Label for="role-name">Name</Label>
			<Input
				id="role-name"
				bind:value={name}
				autocomplete="off"
				disabled={readonlyReason !== null}
				aria-invalid={touched && hints.name !== null}
				aria-describedby="role-name-hint"
			/>
			{#if touched && hints.name}
				<p id="role-name-hint" class="text-destructive text-sm">{hints.name}</p>
			{/if}
		</div>
		<div class="grid gap-2">
			<Label for="role-description">Description (optional)</Label>
			<!-- A native textarea, styled like the Input component: shadcn-svelte has a textarea too, but one plain
			     element doesn't need another component. -->
			<textarea
				id="role-description"
				bind:value={description}
				rows="2"
				disabled={readonlyReason !== null}
				aria-invalid={touched && hints.description !== null}
				aria-describedby="role-description-hint"
				class="border-input focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:border-destructive min-h-16 w-full rounded-md border bg-transparent px-2.5 py-1.5 text-base shadow-xs outline-none focus-visible:ring-3 disabled:opacity-50 md:text-sm"
			></textarea>
			{#if touched && hints.description}
				<p id="role-description-hint" class="text-destructive text-sm">{hints.description}</p>
			{/if}
		</div>
	</div>

	<div class="grid gap-2">
		<h2 class="text-base font-semibold">Permissions</h2>
		<p class="text-muted-foreground text-sm">
			You can only grant permissions you hold yourself, where you hold them. The server says which if you try more.
		</p>
		<GrantEditor bind:state={grants} {catalogue} disabled={readonlyReason !== null} />
	</div>

	<div class="flex flex-wrap gap-2">
		{#if !readonlyReason}
			<Button type="submit" disabled={busy || (touched && !ready) || (role !== null && !grantsChanged && !detailsChanged)}>
				{#if busy}Saving…{:else if role}Save{:else}Create role{/if}
			</Button>
		{/if}
		<Button variant="outline" href="/admin/roles">{readonlyReason ? 'Back to roles' : 'Cancel'}</Button>
	</div>
</form>

<ConfirmChangeDialog bind:open={confirmOpen} message={confirmMessage} lose={confirmLose} onconfirm={confirmed} />
