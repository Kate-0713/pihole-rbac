<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { Tabs } from 'bits-ui';
	import { invalidate } from '$app/navigation';
	import DeleteDhcpDialog from '#lib/components/app/delete-dhcp-dialog.svelte';
	import DhcpLeasesTable from '#lib/components/app/dhcp-leases-table.svelte';
	import DhcpSettingsCard from '#lib/components/app/dhcp-settings-card.svelte';
	import DhcpStaticDialog from '#lib/components/app/dhcp-static-dialog.svelte';
	import DhcpStaticTable, { type StaticRow } from '#lib/components/app/dhcp-static-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { canChangeStatic, normalMac, writableProblem, type DHCPLease, type DHCPStaticLease } from '#lib/dhcp.js';
	import { can } from '#lib/permissions.js';
	import { targets, withTarget } from '#lib/stores/targets.svelte.js';
	import { _dhcpKey as dhcpKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	// DHCP isn't mirrored: through a mirrored group the page only reads, member by member, and changes are made on
	// one instance.
	let group = $derived(!!data.target?.startsWith('g-'));
	let settings = $derived(data.settings);
	let instance = $derived(!group ? settings?.instances[0] : undefined);
	let staticInstance = $derived(!group ? data.statics?.instances[0] : undefined);

	let canEdit = $derived(!group && can('dhcp.edit', data.target));
	let canConfigure = $derived(!group && can('dhcp.config', data.target) && instance?.writable === 'ok');
	let editStatics = $derived(canEdit && canChangeStatic(staticInstance));
	let problems = $derived((settings?.instances ?? []).map(writableProblem).filter((p): p is string => p !== null));

	let leases = $derived(data.leases?.leases ?? []);
	let staticRows = $derived<StaticRow[]>(
		(data.statics?.instances ?? []).flatMap((i) => i.static_leases.map((s) => ({ ...s, instance: i.instance, instance_id: i.instance_id })))
	);
	let staticsByInstance = $derived(
		new Map((data.statics?.instances ?? []).map((i) => [i.instance_id, i.static_leases] as [number, DHCPStaticLease[]]))
	);
	// Leases an instance with DHCP off still shows are the lease file's, which may be old.
	let staleOn = $derived((data.leases?.instances ?? []).filter((s) => !s.active && s.included).map((s) => s.instance));
	let leftOut = $derived((data.leases?.instances ?? []).filter((s) => !s.included).map((s) => s.instance));

	let tab = $state('leases');
	let staticOpen = $state(false);
	let editing = $state<DHCPStaticLease | null>(null);
	let prefill = $state<{ mac: string; ip: string; hostname: string } | null>(null);
	let deleteOpen = $state(false);
	let deletingLease = $state<DHCPLease | null>(null);
	let deletingStatic = $state<DHCPStaticLease | null>(null);

	const reload = () => invalidate(dhcpKey);

	function addStatic() {
		editing = null;
		prefill = null;
		staticOpen = true;
	}
	function makeStatic(l: DHCPLease) {
		editing = null;
		prefill = { mac: normalMac(l.hwaddr ?? ''), ip: l.ip, hostname: l.name ?? '' };
		staticOpen = true;
	}
	function editStatic(r: StaticRow) {
		editing = r;
		prefill = null;
		staticOpen = true;
	}
	function removeLease(l: DHCPLease) {
		deletingLease = l;
		deletingStatic = null;
		deleteOpen = true;
	}
	function removeStatic(r: StaticRow) {
		deletingStatic = r;
		deletingLease = null;
		deleteOpen = true;
	}

	const tabClass =
		'text-muted-foreground data-[state=active]:text-foreground data-[state=active]:border-primary -mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium';
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}DHCP · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">DHCP</h1>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the DHCP of {target?.name ?? 'this instance'}.</p>
{:else if data.error || !settings}
	<Alert variant="destructive"><AlertDescription>Couldn't read the DHCP data: {data.error}</AlertDescription></Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<p class="text-muted-foreground text-sm">
		The addresses {target?.name ?? 'this Pi-hole'} hands out to devices on the network. Changing the settings or the static
		leases restarts DNS and DHCP on the Pi-hole for a moment.
	</p>
	{#if group && target}
		<Alert>
			<AlertDescription>
				DHCP isn't mirrored, so {target.name} shows each member's own data and can't change it. To make a change, open one
				Pi-hole:
				{#each settings.instances as i, n (i.instance_id)}
					{n > 0 ? ', ' : ''}<a class="underline underline-offset-4" href={withTarget('/dhcp', `i-${i.instance_id}`)}>{i.instance}</a>
				{/each}.
			</AlertDescription>
		</Alert>
		{#each (settings.members ?? []).filter((m) => m.status !== 'ok') as m (m.instance_id)}
			<Alert variant="destructive">
				<AlertDescription>Couldn't read {m.instance}: {m.error?.message ?? 'it did not answer.'}</AlertDescription>
			</Alert>
		{/each}
	{/if}
	{#if can('dhcp.edit', data.target) || can('dhcp.config', data.target)}
		{#each problems as p (p)}
			<Alert><AlertDescription>{p}</AlertDescription></Alert>
		{/each}
	{/if}
	{#each staleOn as name (name)}
		<Alert>
			<AlertDescription>
				DHCP is off on {name}. Pi-hole still shows the leases in its lease file, which may be old.
			</AlertDescription>
		</Alert>
	{/each}
	{#if leftOut.length > 0}
		<Alert>
			<AlertDescription>
				Leases of {leftOut.join(', ')} are left out: its DHCP is off, so its lease file may be old.
			</AlertDescription>
		</Alert>
	{/if}

	<Tabs.Root bind:value={tab} class="grid gap-4">
		<Tabs.List class="flex border-b" aria-label="DHCP">
			<Tabs.Trigger value="leases" class={tabClass}>Leases ({leases.length})</Tabs.Trigger>
			<Tabs.Trigger value="static" class={tabClass}>Static leases ({staticRows.length})</Tabs.Trigger>
			<Tabs.Trigger value="settings" class={tabClass}>Settings</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="leases" class="grid gap-2">
			<DhcpLeasesTable
				{leases}
				statics={staticsByInstance}
				showInstance={group}
				onstatic={editStatics ? makeStatic : undefined}
				ondelete={canEdit ? removeLease : undefined}
			/>
		</Tabs.Content>

		<Tabs.Content value="static" class="grid gap-2">
			{#if editStatics}
				<div class="flex justify-end">
					<Button size="sm" onclick={addStatic}><PlusIcon /> Add a static lease</Button>
				</div>
			{/if}
			<DhcpStaticTable
				rows={staticRows}
				showInstance={group}
				onedit={editStatics ? editStatic : undefined}
				ondelete={editStatics ? removeStatic : undefined}
			/>
		</Tabs.Content>

		<Tabs.Content value="settings" class="grid gap-4">
			{#if instance}
				<DhcpSettingsCard target={data.target} {instance} canEdit={canConfigure} onsaved={reload} />
			{:else}
				<div class="overflow-x-auto rounded-lg border">
					<table class="w-full text-sm" aria-label="DHCP settings by Pi-hole">
						<thead class="text-muted-foreground text-left">
							<tr><th class="p-2">Pi-hole</th><th class="p-2">DHCP</th><th class="p-2">Range</th><th class="p-2">Router</th><th class="p-2">Lease time</th></tr>
						</thead>
						<tbody>
							{#each settings.instances as i (i.instance_id)}
								<tr class="border-t">
									<td class="p-2">{i.instance}</td>
									<td class="p-2">{i.settings.active ? 'On' : 'Off'}</td>
									<td class="p-2 font-mono">{i.settings.start || '—'} to {i.settings.end || '—'}</td>
									<td class="p-2 font-mono">{i.settings.router || '—'}</td>
									<td class="p-2">{i.settings.lease_time || 'Default'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</Tabs.Content>
	</Tabs.Root>

	{#if !group && data.target && target}
		<DhcpStaticDialog
			bind:open={staticOpen}
			target={data.target}
			targetName={target.name}
			entry={editing}
			{prefill}
			subnet={staticInstance?.subnet ?? null}
			onsaved={reload}
		/>
		<DeleteDhcpDialog
			bind:open={deleteOpen}
			target={data.target}
			targetName={target.name}
			lease={deletingLease}
			staticLease={deletingStatic}
			ondeleted={reload}
		/>
	{/if}
{/if}
