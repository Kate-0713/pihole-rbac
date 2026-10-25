<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import ChannelConfirmDialog from '#lib/components/app/channel-confirm-dialog.svelte';
	import ChannelFormDialog from '#lib/components/app/channel-form-dialog.svelte';
	import ChannelList from '#lib/components/app/channel-list.svelte';
	import ChannelSecretDialog from '#lib/components/app/channel-secret-dialog.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { toInput, type Channel } from '#lib/notifications.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { _channelsKey as channelsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let formOpen = $state(false);
	let editing = $state<Channel | null>(null);
	let secretOpen = $state(false);
	let secretFor = $state<Channel | null>(null);
	let confirmOpen = $state(false);
	let confirmAction = $state<'disable' | 'delete'>('disable');
	let confirming = $state<Channel | null>(null);
	// The channel a test or enable is running on: a test waits for the destination's answer.
	let busy = $state<number | null>(null);

	const reload = () => invalidate(channelsKey);

	function add() {
		editing = null;
		formOpen = true;
	}

	function ask(c: Channel, action: 'disable' | 'delete') {
		confirming = c;
		confirmAction = action;
		confirmOpen = true;
	}

	async function test(c: Channel) {
		busy = c.id;
		try {
			const r = await unwrap(api.POST('/api/v1/notifications/channels/{id}/test', { params: { path: { id: c.id } } }));
			if (r.ok) notices.success(`${c.name}: test message sent.`);
			else notices.error(r.message, `${c.name}: the test message wasn't accepted`);
		} catch (e) {
			notices.error(e, `Couldn't test ${c.name}`);
		} finally {
			busy = null;
		}
	}

	async function enable(c: Channel) {
		busy = c.id;
		try {
			await unwrap(
				api.PUT('/api/v1/notifications/channels/{id}', { params: { path: { id: c.id } }, body: toInput(c, { enabled: true }) })
			);
			notices.success(`${c.name} enabled.`);
			await reload();
		} catch (e) {
			notices.error(e, `Couldn't enable ${c.name}`);
		} finally {
			busy = null;
		}
	}
</script>

<svelte:head>
	<title>Notifications · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-start justify-between gap-2">
	<div class="grid gap-1">
		<h1 class="text-xl font-semibold">Notifications</h1>
		<p class="text-muted-foreground text-sm">
			Discord webhooks and Matrix rooms that are told when chosen events happen.
		</p>
	</div>
	{#if data.allowed && !data.error}
		<Button size="sm" onclick={add}><PlusIcon /> Add a channel</Button>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the notifications.manage permission to manage notifications.</p>
{:else if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load the channels: {data.error}</AlertDescription></Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	{#if data.channels.length === 0}
		<p class="text-muted-foreground text-sm">No channels yet. Add a Discord webhook or a Matrix room, and pick its events.</p>
	{:else}
		<ChannelList
			channels={data.channels}
			canStoreSecrets={data.canStoreSecrets}
			{busy}
			ontest={test}
			onedit={(c) => {
				editing = c;
				formOpen = true;
			}}
			onsecret={(c) => {
				secretFor = c;
				secretOpen = true;
			}}
			onenable={enable}
			ondisable={(c) => ask(c, 'disable')}
			ondelete={(c) => ask(c, 'delete')}
		/>
	{/if}
	<p class="text-muted-foreground text-sm">
		When a channel's destination or secret changes, or it is disabled, deleted or loses events, its current
		destination is told first, so alerts can't be quietly redirected or switched off.
	</p>
	{#if !data.canStoreSecrets}
		<p class="text-muted-foreground text-sm">
			Secrets can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Until then, each channel's secret
			comes from its env variable.
		</p>
	{/if}

	<ChannelFormDialog
		bind:open={formOpen}
		channel={editing}
		events={data.events}
		canStoreSecrets={data.canStoreSecrets}
		onsaved={reload}
	/>
	<ChannelSecretDialog bind:open={secretOpen} channel={secretFor} onsaved={reload} />
	<ChannelConfirmDialog bind:open={confirmOpen} action={confirmAction} channel={confirming} ondone={reload} />
{/if}
