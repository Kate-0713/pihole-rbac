<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import ClientFormDialog from '#lib/components/app/client-form-dialog.svelte';
	import ClientTable from '#lib/components/app/client-table.svelte';
	import MirroredMemberNote from '#lib/components/app/mirrored-member-note.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { can } from '#lib/permissions.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _clientsKey as clientsKey, type PiholeClient } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let canEdit = $derived(can('clients.edit', data.target));

	let formOpen = $state(false);
	let editing = $state<PiholeClient | null>(null);

	function edit(c: PiholeClient) {
		editing = c;
		formOpen = true;
	}
	const reload = () => invalidate(clientsKey);
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Clients · pihole-rbac</title>
</svelte:head>

<div class="grid gap-1">
	<h1 class="text-xl font-semibold">Clients</h1>
	<p class="text-muted-foreground text-sm">
		The devices and networks set up on this Pi-hole, and the groups whose lists apply to them.
	</p>
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the clients of {target?.name ?? 'this instance'}.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>
			<p>Couldn't read the clients: {data.error}</p>
			{#if data.primaryDown}
				<p>
					A mirrored group's lists are read from its primary alone, so they can't be shown until it answers. The
					dashboard still shows the members that answered.
				</p>
			{/if}
		</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	{#if canEdit && target}<MirroredMemberNote {target} />{/if}
	<ClientTable clients={data.clients} groups={data.groups} {canEdit} onedit={edit} />

	{#if canEdit && target}
		<ClientFormDialog
			bind:open={formOpen}
			target={data.target}
			targetName={target.name}
			groups={data.groups}
			client={editing}
			onsaved={reload}
		/>
	{/if}
{/if}
