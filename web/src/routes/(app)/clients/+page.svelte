<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import ClientFormDialog from '#lib/components/app/client-form-dialog.svelte';
	import ClientTable from '#lib/components/app/client-table.svelte';
	import DriftBadge from '#lib/components/app/drift-badge.svelte';
	import MirroredMemberNote from '#lib/components/app/mirrored-member-note.svelte';
	import TempChangeDialog from '#lib/components/app/temp-change-dialog.svelte';
	import TempChangeExtendDialog from '#lib/components/app/temp-change-extend-dialog.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { can } from '#lib/permissions.js';
	import { whileVisible } from '#lib/poll.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { currentFor, type Limits, type TempChange } from '#lib/temp-changes.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';
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

	// Temporary changes (v2.6.0). The list comes with the page's data; `limits` is null when it couldn't be read, which
	// hides the actions that need it.
	let changes = $derived(data.changes?.changes ?? []);
	let limits = $derived<Limits | null>(
		data.changes ? { max_minutes: data.changes.max_minutes, reason_required: data.changes.reason_required } : null
	);
	let tempOpen = $state(false);
	let tempClient = $state<PiholeClient | null>(null);
	let extendOpen = $state(false);
	let extending = $state<TempChange | null>(null);
	// The change being ended or retried: its buttons wait. `now` is when the page last looked, for "time left".
	let working = $state<number | null>(null);
	let now = $state(new Date());
	// The change the Change dialog warns about, while it is open.
	let editingChange = $derived.by(() => {
		const t = editing ? currentFor(changes, editing.client) : null;
		return t?.status === 'active' ? t : null;
	});

	// While a change is active, look again every 30 seconds (the app puts the client back on its own, so the badge
	// should go away without a reload). whileVisible stops while the tab is hidden and when the page is left.
	let anyActive = $derived(changes.some((c) => c.status === 'active'));
	$effect(() => {
		if (!anyActive) return;
		return whileVisible(() => {
			now = new Date();
			void reload();
		}, 30_000);
	});

	function startTemp(c: PiholeClient) {
		tempClient = c;
		tempOpen = true;
	}
	function extend(t: TempChange) {
		extending = t;
		extendOpen = true;
	}
	// End now and Retry run the revert before answering and report each instance, like any other write.
	async function revertNow(t: TempChange, action: 'end' | 'retry') {
		if (!data.target) return;
		const text =
			action === 'end'
				? { done: `${t.client} is back in its groups`, failed: `Couldn't put ${t.client} back` }
				: { done: `${t.client} is back in its groups`, failed: `Couldn't put ${t.client} back yet` };
		working = t.id;
		try {
			// Two calls rather than one with the action in the path: the API client types each path on its own.
			const params = { params: { path: { target: data.target, id: t.id } } };
			const { results } =
				action === 'end'
					? await unwrap(api.POST('/api/v1/targets/{target}/clients/temporary/{id}/end', params))
					: await unwrap(api.POST('/api/v1/targets/{target}/clients/temporary/{id}/retry', params));
			reportResults(results, text);
		} catch (e) {
			reportFailure(e, text);
		} finally {
			working = null;
			await reload();
		}
	}
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Clients · pihole-rbac</title>
</svelte:head>

<div class="grid gap-1">
	<div class="flex items-center gap-2">
		<h1 class="text-xl font-semibold">Clients</h1>
		{#if data.target && !data.error}<DriftBadge target={data.target} drifted={data.drifted} />{/if}
	</div>
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
	<ClientTable
		clients={data.clients}
		groups={data.groups}
		{canEdit}
		onedit={edit}
		{changes}
		{now}
		canTemp={canEdit && limits !== null}
		{working}
		ontemp={startTemp}
		onextend={extend}
		onend={(t) => revertNow(t, 'end')}
		onretry={(t) => revertNow(t, 'retry')}
	/>

	{#if canEdit && target}
		<ClientFormDialog
			bind:open={formOpen}
			target={data.target}
			targetName={target.name}
			groups={data.groups}
			client={editing}
			override={editingChange}
			onsaved={reload}
		/>
		{#if limits}
			<TempChangeDialog
				bind:open={tempOpen}
				target={data.target}
				targetName={target.name}
				groups={data.groups}
				client={tempClient}
				{limits}
				onsaved={reload}
			/>
			<TempChangeExtendDialog bind:open={extendOpen} target={data.target} change={extending} {limits} onsaved={reload} />
		{/if}
	{/if}
{/if}
