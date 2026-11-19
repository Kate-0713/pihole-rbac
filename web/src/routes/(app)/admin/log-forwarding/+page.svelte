<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import LogDestinationConfirmDialog from '#lib/components/app/log-destination-confirm-dialog.svelte';
	import LogDestinationFormDialog from '#lib/components/app/log-destination-form-dialog.svelte';
	import LogDestinationList from '#lib/components/app/log-destination-list.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { toInput, type LogDestination } from '#lib/logdestinations.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { _destinationsKey as destinationsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let formOpen = $state(false);
	let editing = $state<LogDestination | null>(null);
	let confirmOpen = $state(false);
	let confirmAction = $state<'disable' | 'delete'>('disable');
	let confirming = $state<LogDestination | null>(null);
	// The destination a test or enable is running on: a test waits for the collector.
	let busy = $state<number | null>(null);

	const reload = () => invalidate(destinationsKey);

	function ask(d: LogDestination, action: 'disable' | 'delete') {
		confirming = d;
		confirmAction = action;
		confirmOpen = true;
	}

	async function test(d: LogDestination) {
		busy = d.id;
		try {
			const r = await unwrap(api.POST('/api/v1/settings/log-destinations/{id}/test', { params: { path: { id: d.id } } }));
			if (r.ok) notices.success(`${d.name}: ${r.message}`);
			else notices.error(r.message, `${d.name}: the test message wasn't sent`);
		} catch (e) {
			notices.error(e, `Couldn't test ${d.name}`);
		} finally {
			busy = null;
		}
	}

	async function enable(d: LogDestination) {
		busy = d.id;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/log-destinations/{id}', { params: { path: { id: d.id } }, body: toInput(d, { enabled: true }) })
			);
			notices.success(`${d.name} enabled.`);
			await reload();
		} catch (e) {
			notices.error(e, `Couldn't enable ${d.name}`);
		} finally {
			busy = null;
		}
	}
</script>

<svelte:head>
	<title>Log forwarding · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-start justify-between gap-2">
	<div class="grid gap-1">
		<h1 class="text-xl font-semibold">Log forwarding</h1>
		<p class="text-muted-foreground text-sm">Syslog collectors the audit log is sent to, one message per entry.</p>
	</div>
	{#if data.allowed && !data.error}
		<Button
			size="sm"
			onclick={() => {
				editing = null;
				formOpen = true;
			}}><PlusIcon /> Add a destination</Button
		>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the logging.manage permission to manage log forwarding.</p>
{:else if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load the destinations: {data.error}</AlertDescription></Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	{#if data.destinations.length === 0}
		<p class="text-muted-foreground text-sm">No destinations yet. Add a syslog collector, such as Graylog, Wazuh or rsyslog.</p>
	{:else}
		<LogDestinationList
			destinations={data.destinations}
			{busy}
			ontest={test}
			onedit={(d) => {
				editing = d;
				formOpen = true;
			}}
			onenable={enable}
			ondisable={(d) => ask(d, 'disable')}
			ondelete={(d) => ask(d, 'delete')}
		/>
	{/if}
	<p class="text-muted-foreground text-sm">
		Each entry is sent as a syslog message whose text is the entry as JSON, with its ID for removing duplicates. A new
		destination receives entries from the time it is added. When a destination’s address changes, or it is disabled or
		deleted, the place it was sending to is sent what it hadn’t had, up to that change, so the log can’t be quietly
		redirected or switched off.
	</p>

	<LogDestinationFormDialog bind:open={formOpen} destination={editing} onsaved={reload} />
	<LogDestinationConfirmDialog bind:open={confirmOpen} action={confirmAction} destination={confirming} ondone={reload} />
{/if}
