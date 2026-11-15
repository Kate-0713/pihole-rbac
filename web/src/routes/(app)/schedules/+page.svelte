<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import { browserZone } from '#lib/clientreset.js';
	import DeleteScheduleDialog from '#lib/components/app/delete-schedule-dialog.svelte';
	import ScheduleFormDialog from '#lib/components/app/schedule-form-dialog.svelte';
	import ScheduleTable from '#lib/components/app/schedule-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { lengthText, type Schedule } from '#lib/schedules.js';
	import { can } from '#lib/permissions.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _schedulesKey as schedulesKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let list = $derived(data.list);
	// Saving needs the underlying permission too: blocking.toggle for a blocking window, piholegroups.edit for a group.
	let canBlocking = $derived(can('blocking.toggle', data.target));
	let canGroups = $derived(can('piholegroups.edit', data.target));
	let canAdd = $derived(canBlocking || canGroups);
	const browser = browserZone();

	let formOpen = $state(false);
	let editing = $state<Schedule | null>(null);
	let deleteOpen = $state(false);
	let deleting = $state<Schedule | null>(null);

	const reload = () => invalidate(schedulesKey);

	function add() {
		editing = null;
		formOpen = true;
	}
	function edit(s: Schedule) {
		editing = s;
		formOpen = true;
	}
	function remove(s: Schedule) {
		deleting = s;
		deleteOpen = true;
	}
	// Switching a schedule on or off is a change like any other: it acts from its next edge.
	async function toggle(s: Schedule) {
		if (!data.target) return;
		try {
			await unwrap(
				api.PATCH('/api/v1/targets/{target}/schedules/{id}', {
					params: { path: { target: data.target, id: s.id } },
					body: { enabled: !s.enabled }
				})
			);
			notices.success(`Schedule ${s.name} switched ${s.enabled ? 'off' : 'on'}.`);
		} catch (e) {
			notices.error(e, `Couldn't switch ${s.name} ${s.enabled ? 'off' : 'on'}`);
		}
		await reload();
	}
	// A schedule can only be changed by someone who can do what it does; anyone here can delete one.
	let canChange = $derived((s: Schedule) => (s.kind === 'blocking_off' ? canBlocking : canGroups));
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Schedules · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">Schedules</h1>
	{#if list && canAdd}<Button size="sm" onclick={add}><PlusIcon /> Add a schedule</Button>{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't manage the schedules of {target?.name ?? 'this instance'}.</p>
{:else if data.error || !list}
	<Alert variant="destructive"><AlertDescription>Couldn't read the schedules: {data.error}</AlertDescription></Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<p class="text-muted-foreground text-sm">
		Turn blocking off, or a Pi-hole group on or off, for a window every week or once. At the start and end the app
		makes the change; anything changed by hand in between is left alone until the next start or end. A group window
		can be at most {lengthText(list.group_window_max_minutes)} long.
	</p>

	{#if !canBlocking || !canGroups}
		<p class="text-muted-foreground text-sm" data-permission-note>
			{#if !canAdd}
				You can see and delete these schedules. Adding or changing one also needs permission for what it does:
				blocking.toggle for a blocking window, piholegroups.edit for a group window.
			{:else if !canBlocking}
				You can add and change group windows. Blocking windows also need blocking.toggle.
			{:else}
				You can add and change blocking windows. Group windows also need piholegroups.edit.
			{/if}
		</p>
	{/if}

	<ScheduleTable
		schedules={list.schedules}
		label="Schedules"
		{browser}
		canEdit={true}
		{canChange}
		onedit={edit}
		ondelete={remove}
		ontoggle={toggle}
	/>

	{#if list.from_groups.length > 0}
		<section class="grid gap-2" aria-labelledby="schedules-from-groups">
			<h2 id="schedules-from-groups" class="font-semibold">From mirrored groups</h2>
			<p class="text-muted-foreground text-sm">
				These are set on a mirrored group {target?.name ?? 'this instance'} belongs to, and apply to it too. Change them
				with the group selected.
			</p>
			<ScheduleTable schedules={list.from_groups} label="Schedules from mirrored groups" {browser} canEdit={false} />
		</section>
	{/if}

	{#if target}
		<ScheduleFormDialog
			bind:open={formOpen}
			target={data.target}
			targetName={target.name}
			schedule={editing}
			groups={data.groups}
			groupMax={list.group_window_max_minutes}
			{canBlocking}
			{canGroups}
			onsaved={reload}
		/>
	{/if}
	<DeleteScheduleDialog bind:open={deleteOpen} target={data.target} schedule={deleting} ondeleted={reload} />
{/if}
