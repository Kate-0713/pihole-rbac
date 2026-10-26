<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import GroupDeleteDialog from '#lib/components/app/group-delete-dialog.svelte';
	import GroupFormDialog from '#lib/components/app/group-form-dialog.svelte';
	import GroupTable from '#lib/components/app/group-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import type { Group } from '#lib/groups.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { _groupsKey as groupsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let formOpen = $state(false);
	let editing = $state<Group | null>(null);
	let deleteOpen = $state(false);
	let deleting = $state<Group | null>(null);

	// After a change, read the groups again, and the header's targets and the permissions on them too: mirrored groups
	// are targets.
	async function reload() {
		await invalidate(groupsKey);
		try {
			await session.refreshTargets();
		} catch {
			// The picker keeps its old list; the page itself is up to date.
		}
	}

	function add() {
		editing = null;
		formOpen = true;
	}
	function edit(g: Group) {
		editing = g;
		formOpen = true;
	}
	function remove(g: Group) {
		deleting = g;
		deleteOpen = true;
	}
</script>

<svelte:head>
	<title>Groups · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">Groups</h1>
	{#if data.allowed && !data.error}
		<Button size="sm" onclick={add}><PlusIcon /> Add a group</Button>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the instances.manage permission to manage groups.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the groups: {data.error}</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<p class="text-muted-foreground max-w-prose text-sm">
		An independent group is a label: a permission granted on it covers each member. A mirrored group runs its
		members as one Pi-hole, with changes going to every enabled member and the primary as the source of truth.
	</p>
	{#if data.groups.length === 0}
		<p class="text-muted-foreground text-sm">No groups yet.</p>
	{:else}
		<GroupTable groups={data.groups} onedit={edit} ondelete={remove} />
	{/if}

	<GroupFormDialog
		bind:open={formOpen}
		group={editing}
		groups={data.groups}
		instances={data.instances}
		onsaved={reload}
	/>
	<GroupDeleteDialog bind:open={deleteOpen} group={deleting} ondone={reload} />
{/if}
