<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import LDAPMappings from '#lib/components/app/ldap-mappings.svelte';
	import LDAPSettingsForm from '#lib/components/app/ldap-settings-form.svelte';
	import LDAPTestUser from '#lib/components/app/ldap-test-user.svelte';
	import LoginMethodsCard from '#lib/components/app/login-methods-card.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { _ldapKey as ldapKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const reload = () => invalidate(ldapKey);
</script>

<svelte:head>
	<title>LDAP · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">LDAP</h1>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the settings.manage or roles.manage permission to use this page.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the LDAP settings: {data.error}</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<div class="grid gap-6 lg:grid-cols-2 lg:items-start">
		{#if data.settings}
			<div class="grid gap-6">
				<LoginMethodsCard
					methods={data.settings.methods}
					ldapConfigured={data.settings.ldap.settings !== undefined}
					onsaved={reload}
				/>
				<LDAPSettingsForm view={data.settings.ldap} onsaved={reload} />
			</div>
		{/if}
		{#if data.mappings}
			<div class="grid gap-6">
				<LDAPMappings mappings={data.mappings.mappings} roles={data.mappings.roles} onchanged={reload} />
				<LDAPTestUser />
			</div>
		{/if}
	</div>
	{#if !data.settings}
		<p class="text-muted-foreground text-sm">The LDAP server and login methods need the settings.manage permission.</p>
	{/if}
{/if}
