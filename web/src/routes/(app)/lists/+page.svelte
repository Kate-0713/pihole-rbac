<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import DeleteListDialog from '#lib/components/app/delete-list-dialog.svelte';
	import DriftBadge from '#lib/components/app/drift-badge.svelte';
	import GravityPanel from '#lib/components/app/gravity-panel.svelte';
	import ListFormDialog from '#lib/components/app/list-form-dialog.svelte';
	import ListTable from '#lib/components/app/list-table.svelte';
	import MirroredMemberNote from '#lib/components/app/mirrored-member-note.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { listKey, waitingCount, type GravityRun, type PiholeList } from '#lib/lists.js';
	import { can } from '#lib/permissions.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';
	import { _listsKey as listsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let canEdit = $derived(can('lists.edit', data.target));
	let canRun = $derived(can('gravity.run', data.target));
	let several = $derived(!!data.target?.startsWith('g-'));

	let formOpen = $state(false);
	let editing = $state<PiholeList | null>(null);
	let deleteOpen = $state(false);
	let deleting = $state<PiholeList | null>(null);
	let toggling = $state<string | null>(null);

	// The run the panel follows: one started here, or the target's latest while it's still running when the page
	// loads. The panel says when it has finished (ondone), which is what turns the Run gravity button back on.
	// Closing the panel only hides it: the run goes on, and the panel keeps following it.
	let followed = $state<GravityRun | null>(null);
	let closedRun = $state<string | null>(null);
	let shownRun = $derived.by(() => {
		if (followed?.target === data.target) return followed;
		return data.latestRun?.status === 'running' ? data.latestRun : null;
	});
	let running = $derived(shownRun?.status === 'running');

	async function finished(run: GravityRun) {
		followed = run;
		await reload();
	}

	const reload = () => invalidate(listsKey);

	function add() {
		editing = null;
		formOpen = true;
	}
	function edit(l: PiholeList) {
		editing = l;
		formOpen = true;
	}
	function remove(l: PiholeList) {
		deleting = l;
		deleteOpen = true;
	}

	async function toggle(l: PiholeList) {
		if (!data.target) return;
		const target = data.target;
		const enabled = !l.enabled;
		toggling = listKey(l);
		const text = {
			done: `${l.address} ${enabled ? 'enabled' : 'disabled'}`,
			failed: `Couldn't ${enabled ? 'enable' : 'disable'} ${l.address}`
		};
		const send = async (members?: number[]) =>
			(
				await unwrap(
					api.PATCH('/api/v1/targets/{target}/lists', {
						params: { path: { target }, query: members ? { members } : undefined },
						body: { address: l.address, type: l.type, enabled }
					})
				)
			).results;
		const retry = { retry: send, after: reload };
		try {
			const results = await send();
			reportResults(results, text, retry);
			// A list enabled again is only used once gravity has downloaded it.
			if (enabled && results.some((r) => r.status === 'ok' && r.entry?.needs_gravity)) {
				notices.info('Pi-hole starts using it after the next gravity update.');
			}
		} catch (e) {
			reportFailure(e, text, retry);
		} finally {
			toggling = null;
			await reload();
		}
	}

	let confirmOpen = $state(false);
	let starting = $state(false);
	async function runGravity(event: MouseEvent) {
		event.preventDefault();
		if (!data.target) return;
		starting = true;
		try {
			followed = await unwrap(api.POST('/api/v1/targets/{target}/gravity', { params: { path: { target: data.target } } }));
			closedRun = null;
			confirmOpen = false;
		} catch (e) {
			notices.error(e, "Couldn't start gravity");
			confirmOpen = false;
		} finally {
			starting = false;
		}
	}

	let waiting = $derived(waitingCount(data.lists));
	let unreadable = $derived((data.members ?? []).filter((m) => m.status !== 'ok'));
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Lists · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<div class="flex items-center gap-2">
		<h1 class="text-xl font-semibold">Lists</h1>
		{#if data.target && !data.error}<DriftBadge target={data.target} drifted={data.drifted} />{/if}
	</div>
	{#if data.target && !data.error && data.allowed}
		<div class="flex flex-wrap gap-2">
			{#if canRun}
				<Button variant="outline" size="sm" onclick={() => (confirmOpen = true)} disabled={running || starting}>
					<RefreshCwIcon class={running ? 'animate-spin' : ''} />
					{running ? 'Gravity is running…' : 'Run gravity'}
				</Button>
			{/if}
			{#if canEdit}<Button size="sm" onclick={add}><PlusIcon /> Add a list</Button>{/if}
		</div>
	{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the lists of {target?.name ?? 'this instance'}.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>
			<p>Couldn't read the lists: {data.error}</p>
			{#if data.primaryDown}
				<p>A mirrored group's lists are read from its primary, so they can't be shown until it answers.</p>
			{/if}
		</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<p class="text-muted-foreground text-sm">
		The blocklists and allowlists {target?.name ?? 'this instance'} subscribes to. Pi-hole downloads them during a
		gravity update{data.gravityLastUpdate ? `, last finished ${formatDateTime(data.gravityLastUpdate)}` : ''}.
		Disabling a list or changing its groups applies at once; a new list, or one enabled again, waits for gravity.
	</p>
	{#each unreadable as m (m.instance)}
		<Alert>
			<AlertDescription>
				{m.instance} couldn't be read{m.error ? `: ${m.error.message}` : '.'} Its own status for each list isn't shown.
			</AlertDescription>
		</Alert>
	{/each}
	{#if waiting > 0 && !running}
		<Alert>
			<AlertDescription class="flex flex-wrap items-center justify-between gap-2">
				<span>
					{waiting === 1 ? '1 list is' : `${waiting} lists are`} waiting for a gravity update{canRun
						? '.'
						: '. Someone with gravity.run on this target can start one.'}
				</span>
				{#if canRun}
					<Button size="sm" onclick={() => (confirmOpen = true)} disabled={starting}>Run gravity now</Button>
				{/if}
			</AlertDescription>
		</Alert>
	{/if}

	{#if shownRun && data.target}
		<GravityPanel
			target={data.target}
			run={shownRun}
			hidden={shownRun.id === closedRun}
			ondone={finished}
			onclose={() => (closedRun = shownRun?.id ?? null)}
		/>
	{/if}

	{#if canEdit && target}<MirroredMemberNote {target} />{/if}
	<ListTable
		lists={data.lists}
		groups={data.groups}
		{canEdit}
		busy={toggling}
		onedit={edit}
		ontoggle={toggle}
		ondelete={remove}
	/>

	{#if canEdit && target}
		<ListFormDialog
			bind:open={formOpen}
			target={data.target}
			targetName={target.name}
			groups={data.groups}
			list={editing}
			onsaved={reload}
		/>
		<DeleteListDialog
			bind:open={deleteOpen}
			target={data.target}
			targetName={target.name}
			list={deleting}
			ondeleted={reload}
		/>
	{/if}

	{#if canRun && target}
		<AlertDialog.Root bind:open={confirmOpen}>
			<AlertDialog.Content>
				<AlertDialog.Header>
					<AlertDialog.Title>Run gravity on {target.name}?</AlertDialog.Title>
					<AlertDialog.Description>
						Pi-hole downloads every enabled list again and rebuilds its blocking database, which can take a few
						minutes. It keeps blocking with the old lists meanwhile.
						{#if several}
							The members are updated one at a time, the primary first, and the run stops at the first one that fails,
							so the rest keep their current lists.
						{/if}
					</AlertDialog.Description>
				</AlertDialog.Header>
				<AlertDialog.Footer>
					<AlertDialog.Cancel disabled={starting}>Cancel</AlertDialog.Cancel>
					<AlertDialog.Action disabled={starting} onclick={runGravity}>
						{starting ? 'Starting…' : 'Run gravity'}
					</AlertDialog.Action>
				</AlertDialog.Footer>
			</AlertDialog.Content>
		</AlertDialog.Root>
	{/if}
{/if}
