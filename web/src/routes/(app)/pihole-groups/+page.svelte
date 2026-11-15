<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import DriftBadge from '#lib/components/app/drift-badge.svelte';
	import MirroredMemberNote from '#lib/components/app/mirrored-member-note.svelte';
	import PiholeGroupDeleteDialog from '#lib/components/app/pihole-group-delete-dialog.svelte';
	import PiholeGroupFormDialog from '#lib/components/app/pihole-group-form-dialog.svelte';
	import PiholeGroupTable from '#lib/components/app/pihole-group-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import { can } from '#lib/permissions.js';
	import type { PiholeGroup } from '#lib/pihole.js';
	import { confirmationOf, defaultGroupID } from '#lib/pihole-groups.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';
	import { _groupsKey as groupsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let canEdit = $derived(can('piholegroups.edit', data.target));

	let formOpen = $state(false);
	let editing = $state<PiholeGroup | null>(null);
	let deleteOpen = $state(false);
	let deleting = $state<PiholeGroup | null>(null);
	// Switching the Default group off asks first: it turns filtering off for most clients.
	let defaultOffOpen = $state(false);
	let toggling = $state<string | null>(null);

	const reload = () => invalidate(groupsKey);

	function add() {
		editing = null;
		formOpen = true;
	}
	function edit(g: PiholeGroup) {
		editing = g;
		formOpen = true;
	}
	function remove(g: PiholeGroup) {
		deleting = g;
		deleteOpen = true;
	}
	function toggle(g: PiholeGroup) {
		if (g.id === defaultGroupID && g.enabled) {
			defaultOffOpen = true;
			return;
		}
		void setEnabled(g, !g.enabled, false);
	}

	async function setEnabled(g: PiholeGroup, enabled: boolean, confirm: boolean) {
		if (!data.target) return;
		toggling = g.name;
		const target = data.target;
		const text = { done: `${g.name} ${enabled ? 'enabled' : 'disabled'}`, failed: `Couldn't ${enabled ? 'enable' : 'disable'} ${g.name}` };
		const send = async (members?: number[]) =>
			(
				await unwrap(
					api.PATCH('/api/v1/targets/{target}/groups', {
						params: { path: { target }, query: { ...(members ? { members } : {}), ...(confirm ? { confirm: true } : {}) } },
						body: { name: g.name, enabled }
					})
				)
			).results;
		const retry = { retry: send, after: reload };
		try {
			reportResults(await send(), text, retry);
		} catch (e) {
			// Only the Default group needs confirming, and it was asked about above; anything else is a failure.
			if (confirmationOf(e)) defaultOffOpen = true;
			else reportFailure(e, text, retry);
		} finally {
			toggling = null;
			await reload();
		}
	}

	let defaultGroup = $derived(data.groups.find((g) => g.id === defaultGroupID));
	async function confirmDefaultOff(event: MouseEvent) {
		event.preventDefault();
		defaultOffOpen = false;
		if (defaultGroup) await setEnabled(defaultGroup, false, true);
		else notices.error("The Default group isn't in the list any more.");
	}
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Pi-hole groups · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<div class="flex items-center gap-2">
		<h1 class="text-xl font-semibold">Pi-hole groups</h1>
		{#if data.target && !data.error}<DriftBadge target={data.target} drifted={data.drifted} />{/if}
	</div>
	{#if canEdit && data.target && !data.error}
		<Button size="sm" onclick={add}><PlusIcon /> Add a Pi-hole group</Button>
	{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the Pi-hole groups of {target?.name ?? 'this instance'}.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>
			<p>Couldn't read the Pi-hole groups: {data.error}</p>
			{#if data.primaryDown}
				<p>A mirrored group's Pi-hole groups are read from its primary alone, so they can't be shown until it answers.</p>
			{/if}
		</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<p class="text-muted-foreground text-sm">
		Pi-hole's own groups, which domains, clients and lists are put in. Turning a group off changes blocking for every
		client in it.
	</p>
	{#if canEdit && target}<MirroredMemberNote {target} />{/if}
	<PiholeGroupTable groups={data.groups} {canEdit} busy={toggling} onedit={edit} ontoggle={toggle} ondelete={remove} />

	{#if canEdit && target}
		<PiholeGroupFormDialog bind:open={formOpen} target={data.target} targetName={target.name} group={editing} onsaved={reload} />
		<PiholeGroupDeleteDialog
			bind:open={deleteOpen}
			target={data.target}
			targetName={target.name}
			group={deleting}
			ondeleted={reload}
		/>
		<AlertDialog.Root bind:open={defaultOffOpen}>
			<AlertDialog.Content>
				<AlertDialog.Header>
					<AlertDialog.Title>Disable the Default group?</AlertDialog.Title>
					<AlertDialog.Description>
						Domains and lists assigned only to Default stop applying to the clients in it. On most installs that turns
						filtering off for the whole network of {target.name}.
					</AlertDialog.Description>
				</AlertDialog.Header>
				<AlertDialog.Footer>
					<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
					<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} onclick={confirmDefaultOff}>
						Disable Default
					</AlertDialog.Action>
				</AlertDialog.Footer>
			</AlertDialog.Content>
		</AlertDialog.Root>
	{/if}
{/if}
