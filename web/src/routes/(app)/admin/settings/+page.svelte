<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import GeneralSettingsCard from '#lib/components/app/general-settings-card.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { _settingsKey as settingsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head>
	<title>Settings · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">Settings</h1>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the settings.manage permission to change the settings.</p>
{:else if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load the settings: {data.error}</AlertDescription></Alert>
{:else if data.general}
	<div class="grid gap-6 lg:max-w-2xl">
		<GeneralSettingsCard settings={data.general} onsaved={() => invalidate(settingsKey)} />
		<p class="text-muted-foreground text-sm">
			Login methods and the LDAP server are on the <a class="underline" href="/admin/ldap">LDAP</a> page.
		</p>
	</div>
{/if}
