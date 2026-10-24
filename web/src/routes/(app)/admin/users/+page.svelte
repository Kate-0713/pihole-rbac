<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import UserConfirmDialog from '#lib/components/app/user-confirm-dialog.svelte';
	import UserCreateDialog from '#lib/components/app/user-create-dialog.svelte';
	import UserPasswordDialog from '#lib/components/app/user-password-dialog.svelte';
	import UserRolesDialog from '#lib/components/app/user-roles-dialog.svelte';
	import UserTable from '#lib/components/app/user-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { isSelf, type User } from '#lib/users.js';
	import { _usersKey as usersKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let createOpen = $state(false);
	let rolesOpen = $state(false);
	let passwordOpen = $state(false);
	let confirmOpen = $state(false);
	let confirmAction = $state<'disable' | 'delete'>('disable');
	// The user the open dialog is about. One variable serves every dialog, since only one is open at a time.
	let target = $state<User | null>(null);
	let busy = $state<number | null>(null);

	let selfID = $derived(session.user?.id);
	let targetIsSelf = $derived(target !== null && isSelf(target, selfID));

	function open(u: User, which: 'roles' | 'password') {
		target = u;
		if (which === 'roles') rolesOpen = true;
		else passwordOpen = true;
	}
	function ask(u: User, action: 'disable' | 'delete') {
		target = u;
		confirmAction = action;
		confirmOpen = true;
	}

	// After a change: read the list again and, if it was to your own account, your session too, so the nav follows
	// your new roles (or, if the account was disabled or deleted, the 401 sends you to the login page).
	async function reload(self = false) {
		if (self) {
			await Promise.allSettled([session.refresh(), targets.refresh()]);
			if (session.status !== 'authenticated') return;
		}
		await invalidate(usersKey);
	}

	async function enable(u: User) {
		busy = u.id;
		try {
			await unwrap(api.POST('/api/v1/users/{id}/enable', { params: { path: { id: u.id } } }));
			notices.success(`${u.username} enabled.`);
			await reload();
		} catch (e) {
			notices.error(e, `Couldn't enable ${u.username}`);
		} finally {
			busy = null;
		}
	}
</script>

<svelte:head>
	<title>Users · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">Users</h1>
	{#if data.allowed && !data.error}
		<Button size="sm" onclick={() => (createOpen = true)}><PlusIcon /> New user</Button>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the users.manage permission to manage users.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the users: {data.error}</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={() => reload()}>Try again</Button>
{:else}
	<UserTable
		users={data.users}
		{selfID}
		{busy}
		onroles={(u) => open(u, 'roles')}
		onpassword={(u) => open(u, 'password')}
		onenable={enable}
		ondisable={(u) => ask(u, 'disable')}
		ondelete={(u) => ask(u, 'delete')}
	/>
	<p class="text-muted-foreground text-sm">
		LDAP users get an account when they first log in, with roles from the LDAP group mappings; their roles show while
		they are logged in. Change your own password from the account menu.
	</p>

	<UserCreateDialog bind:open={createOpen} roles={data.roles} onsaved={() => reload()} />
	<UserRolesDialog bind:open={rolesOpen} user={target} roles={data.roles} onsaved={() => reload(targetIsSelf)} />
	<UserPasswordDialog bind:open={passwordOpen} user={target} />
	<UserConfirmDialog
		bind:open={confirmOpen}
		action={confirmAction}
		user={target}
		self={targetIsSelf}
		ondone={() => reload(targetIsSelf)}
	/>
{/if}
