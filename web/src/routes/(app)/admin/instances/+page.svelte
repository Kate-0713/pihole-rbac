<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import InstanceConfirmDialog from '#lib/components/app/instance-confirm-dialog.svelte';
	import InstanceFormDialog from '#lib/components/app/instance-form-dialog.svelte';
	import InstancePasswordDialog from '#lib/components/app/instance-password-dialog.svelte';
	import InstanceTable from '#lib/components/app/instance-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { errorLabel, type Instance } from '#lib/instances.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { _instancesKey as instancesKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let formOpen = $state(false);
	let editing = $state<Instance | null>(null);
	let passwordOpen = $state(false);
	let passwordFor = $state<Instance | null>(null);
	let confirmOpen = $state(false);
	let confirmAction = $state<'disable' | 'delete'>('disable');
	let confirming = $state<Instance | null>(null);
	// The instance a test or enable is running on: both talk to the Pi-hole and can take a few seconds.
	let busy = $state<number | null>(null);

	// After a change, read the list again, and the header's target list too: enabling, disabling, renaming and
	// deleting all change what the picker offers.
	async function reload() {
		await invalidate(instancesKey);
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
	function edit(inst: Instance) {
		editing = inst;
		formOpen = true;
	}
	function changePassword(inst: Instance) {
		passwordFor = inst;
		passwordOpen = true;
	}
	function ask(inst: Instance, action: 'disable' | 'delete') {
		confirming = inst;
		confirmAction = action;
		confirmOpen = true;
	}

	// detailed adds the underlying error (a TLS or connection error, say) to the server's message.
	function detailed(message: string, detail: unknown): string {
		return typeof detail === 'string' && detail !== '' ? `${message} (${detail})` : message;
	}

	async function test(inst: Instance) {
		busy = inst.id;
		try {
			const result = await unwrap(api.POST('/api/v1/instances/{id}/test', { params: { path: { id: inst.id } } }));
			if (result.ok) {
				notices.success(`${inst.name}: the connection works.`);
			} else {
				const message = result.error?.message ?? errorLabel(result.error?.code) ?? 'The test failed.';
				notices.error(detailed(message, result.error?.detail), `${inst.name}: connection test failed`);
			}
		} catch (e) {
			notices.error(e, `Couldn't test ${inst.name}`);
		} finally {
			busy = null;
		}
	}

	async function enable(inst: Instance) {
		busy = inst.id;
		try {
			await unwrap(api.POST('/api/v1/instances/{id}/enable', { params: { path: { id: inst.id } } }));
			notices.success(`${inst.name} enabled.`);
			await reload();
		} catch (e) {
			if (e instanceof ApiError) notices.error(detailed(e.message, e.details.detail), `Couldn't enable ${inst.name}`);
			else notices.error(e, `Couldn't enable ${inst.name}`);
		} finally {
			busy = null;
		}
	}
</script>

<svelte:head>
	<title>Instances · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">Instances</h1>
	{#if data.allowed && !data.error}
		<Button size="sm" onclick={add}><PlusIcon /> Add an instance</Button>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the instances.manage permission to manage instances.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the instances: {data.error}</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	{#if data.instances.length === 0}
		<p class="text-muted-foreground text-sm">
			No Pi-hole instances yet. Add one with its app password, then enable it.
		</p>
	{:else}
		<InstanceTable
			instances={data.instances}
			{busy}
			onedit={edit}
			onpassword={changePassword}
			ontest={test}
			onenable={enable}
			ondisable={(i) => ask(i, 'disable')}
			ondelete={(i) => ask(i, 'delete')}
		/>
	{/if}

	{#if !data.canStorePasswords}
		<p class="text-muted-foreground text-sm">
			Passwords can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Until then, each instance's
			password comes from its env variable.
		</p>
	{/if}

	<InstanceFormDialog
		bind:open={formOpen}
		instance={editing}
		canStorePasswords={data.canStorePasswords}
		onsaved={reload}
	/>
	<InstancePasswordDialog bind:open={passwordOpen} instance={passwordFor} onsaved={reload} />
	<InstanceConfirmDialog bind:open={confirmOpen} action={confirmAction} instance={confirming} ondone={reload} />
{/if}
