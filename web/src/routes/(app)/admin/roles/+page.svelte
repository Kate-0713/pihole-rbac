<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { summarise, type Role } from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { _rolesKey as rolesKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let deleteOpen = $state(false);
	let deleting = $state<Role | null>(null);
	let deleteError = $state<string | null>(null);
	let busy = $state(false);

	function askDelete(r: Role) {
		deleting = r;
		deleteError = null;
		deleteOpen = true;
	}

	async function remove(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open until the answer is known
		if (!deleting) return;
		busy = true;
		try {
			await unwrap(api.DELETE('/api/v1/roles/{id}', { params: { path: { id: deleting.id } } }));
			notices.success(`Role ${deleting.name} deleted.`);
			deleteOpen = false;
			await invalidate(rolesKey);
		} catch (e) {
			deleteError = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}

	// Who uses a role, in a few words for the table.
	function usedBy(r: Role): string {
		const parts: string[] = [];
		if (r.users.length > 0) parts.push(r.users.join(', '));
		if (r.ldap_groups.length > 0) parts.push(`${r.ldap_groups.length} LDAP group${r.ldap_groups.length === 1 ? '' : 's'}`);
		return parts.join('; ') || 'Nobody';
	}
</script>

<svelte:head>
	<title>Roles · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">Roles</h1>
	{#if data.allowed && !data.error}
		<Button size="sm" href="/admin/roles/new"><PlusIcon /> New role</Button>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the roles.manage permission to manage roles.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the roles: {data.error}</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={() => invalidate(rolesKey)}>Try again</Button>
{:else}
	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head>Role</Table.Head>
					<Table.Head>Permissions</Table.Head>
					<Table.Head>Used by</Table.Head>
					<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each data.roles as r (r.id)}
					{@const lines = r.builtin ? ['Every permission, everywhere'] : summarise(r.grants, data.catalogue)}
					<Table.Row>
						<Table.Cell class="align-top">
							<a href="/admin/roles/{r.id}" class="font-medium underline-offset-4 hover:underline">{r.name}</a>
							{#if r.builtin}<Badge variant="secondary" class="ml-1">Builtin</Badge>{/if}
							{#if r.description}<p class="text-muted-foreground text-xs">{r.description}</p>{/if}
						</Table.Cell>
						<Table.Cell class="align-top">
							{#if lines.length === 0}
								<span class="text-muted-foreground text-sm">None</span>
							{:else}
								<ul class="text-sm">
									{#each lines as line (line)}<li class="font-mono text-xs">{line}</li>{/each}
								</ul>
							{/if}
						</Table.Cell>
						<Table.Cell class="align-top text-sm">{usedBy(r)}</Table.Cell>
						<Table.Cell class="align-top">
							<div class="flex gap-1">
								<Button variant="ghost" size="sm" href="/admin/roles/{r.id}" aria-label="Open {r.name}">
									{r.builtin || !r.manageable ? 'View' : 'Edit'}
								</Button>
								{#if !r.builtin && r.manageable}
									<Button variant="ghost" size="sm" onclick={() => askDelete(r)} aria-label="Delete {r.name}">Delete</Button>
								{/if}
							</div>
						</Table.Cell>
					</Table.Row>
				{/each}
			</Table.Body>
		</Table.Root>
	</div>
{/if}

<AlertDialog.Root bind:open={deleteOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Delete the role {deleting?.name}?</AlertDialog.Title>
			<AlertDialog.Description>
				Its permissions go with it. A role that users or LDAP groups still have can't be deleted: take it from them
				first.
			</AlertDialog.Description>
		</AlertDialog.Header>
		{#if deleteError}
			<Alert variant="destructive">
				<AlertDescription>{deleteError}</AlertDescription>
			</Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={remove}>
				{busy ? 'Deleting…' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
