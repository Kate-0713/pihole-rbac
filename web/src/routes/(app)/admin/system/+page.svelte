<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import RestartCard from '#lib/components/app/restart-card.svelte';
	import SecretsCard from '#lib/components/app/secrets-card.svelte';
	import UpdateCard from '#lib/components/app/update-card.svelte';
	import VersionCard from '#lib/components/app/version-card.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { can } from '#lib/permissions.js';
	import { _systemKey as systemKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const reload = () => invalidate(systemKey);
</script>

<svelte:head>
	<title>System · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">System</h1>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the app.update or config.reload permission to see this page.</p>
{:else}
	<div class="grid gap-6 lg:max-w-3xl">
		{#if data.version?.value}
			<VersionCard version={data.version.value} />
		{:else if data.version?.error}
			<Alert variant="destructive"><AlertDescription>Couldn't load the version: {data.version.error}</AlertDescription></Alert>
		{/if}

		{#if data.update?.value}
			<!-- {#key} makes a fresh card when the page reloads its data, so the card starts from the new status. -->
			{#key data.update.value}
				<UpdateCard initial={data.update.value} />
			{/key}
		{:else if data.update?.error}
			<Alert variant="destructive"><AlertDescription>Couldn't load the update status: {data.update.error}</AlertDescription></Alert>
		{/if}

		{#if can('app.update')}
			<RestartCard install={data.update?.value?.install ?? null} onrestarted={reload} />
		{/if}

		{#if data.secrets?.value}
			<SecretsCard secrets={data.secrets.value} onreloaded={reload} />
		{:else if data.secrets?.error}
			<Alert variant="destructive"><AlertDescription>Couldn't load the secrets: {data.secrets.error}</AlertDescription></Alert>
		{/if}
	</div>
{/if}
