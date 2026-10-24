<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import DeleteDomainDialog from '#lib/components/app/delete-domain-dialog.svelte';
	import DomainFormDialog from '#lib/components/app/domain-form-dialog.svelte';
	import DomainTable from '#lib/components/app/domain-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import type { Domain } from '#lib/domains.js';
	import { can } from '#lib/permissions.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _domainsKey as domainsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let canEdit = $derived(can('domains.edit', data.target));

	// Which dialog is open, and for which entry. One of each dialog for the whole page, rather than one per row.
	let formOpen = $state(false);
	let editing = $state<Domain | null>(null);
	let deleteOpen = $state(false);
	let deleting = $state<Domain | null>(null);

	function add() {
		editing = null;
		formOpen = true;
	}
	function edit(d: Domain) {
		editing = d;
		formOpen = true;
	}
	function remove(d: Domain) {
		deleting = d;
		deleteOpen = true;
	}
	const reload = () => invalidate(domainsKey);
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Domains · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">Domains</h1>
	{#if canEdit && data.target && !data.error}
		<Button size="sm" onclick={add}><PlusIcon /> Add a domain</Button>
	{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the domain lists of {target?.name ?? 'this instance'}.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't read the domain lists: {data.error}</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<DomainTable domains={data.domains} groups={data.groups} {canEdit} onedit={edit} ondelete={remove} />

	{#if canEdit && target}
		<DomainFormDialog
			bind:open={formOpen}
			target={data.target}
			targetName={target.name}
			groups={data.groups}
			entry={editing}
			onsaved={reload}
		/>
		<DeleteDomainDialog
			bind:open={deleteOpen}
			target={data.target}
			targetName={target.name}
			entry={deleting}
			ondeleted={reload}
		/>
	{/if}
{/if}
