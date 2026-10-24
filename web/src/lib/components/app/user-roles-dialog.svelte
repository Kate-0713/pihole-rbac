<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription, AlertTitle } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { needsConfirmation, wouldLose, type Role } from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { sameRoles, type User } from '#lib/users.js';
	import RoleChecklist from './role-checklist.svelte';

	// Changes a local user's roles. Their sessions get the new roles at once. A change that would take away your own
	// roles.manage or users.manage is answered with confirmation_required; the dialog then says what you'd lose, and
	// "Save anyway" repeats the request with ?confirm=true. (In the dialog rather than a second one on top of it.)
	let {
		open = $bindable(false),
		user,
		roles,
		onsaved
	}: {
		open: boolean;
		user: User | null;
		roles: Role[];
		onsaved: (u: User) => Promise<void> | void;
	} = $props();

	let selected = $state<number[]>([]);
	let error = $state<string | null>(null);
	let confirm = $state<{ message: string; lose: string[]; roles: number[] } | null>(null);
	let busy = $state(false);

	$effect(() => {
		if (!open || !user) return;
		selected = user.roles.map((r) => r.id);
		error = null;
		confirm = null;
	});

	// A confirmation is for the roles it was asked about; ticking anything else needs asking again.
	let confirming = $derived(confirm && sameRoles(confirm.roles, selected) ? confirm : null);
	let changed = $derived(user !== null && !sameRoles(selected, user.roles.map((r) => r.id)));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!user || !changed) return;
		busy = true;
		error = null;
		try {
			const saved = await unwrap(
				api.PUT('/api/v1/users/{id}/roles', {
					params: { path: { id: user.id }, query: confirming ? { confirm: true } : {} },
					body: { role_ids: selected }
				})
			);
			notices.success(`Roles of ${saved.username} saved.`);
			open = false;
			await onsaved(saved);
		} catch (e) {
			if (needsConfirmation(e)) {
				confirm = { message: e.message, lose: wouldLose(e), roles: [...selected] };
			} else {
				error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
			}
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Roles of {user?.username}</Dialog.Title>
			<Dialog.Description>
				The user's sessions get the new roles at once. With no role, they are logged out and can't log in.
			</Dialog.Description>
		</Dialog.Header>

		<form id="user-roles-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}
			<RoleChecklist bind:selected {roles} disabled={busy} />
			{#if confirming}
				<Alert variant="destructive">
					<AlertTitle>Remove your own access?</AlertTitle>
					<AlertDescription>
						<p>{confirming.message}</p>
						{#if confirming.lose.length > 0}
							<p>
								You would lose: {#each confirming.lose as p, i (p)}<code>{p}</code>{i < confirming.lose.length - 1
										? ', '
										: ''}{/each}. Only someone who still holds it can give it back.
							</p>
						{/if}
					</AlertDescription>
				</Alert>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button
				type="submit"
				form="user-roles-form"
				variant={confirming ? 'destructive' : 'default'}
				disabled={busy || !changed}
			>
				{#if busy}Saving…{:else if confirming}Save anyway{:else}Save{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
