<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import RoleEditor from '#lib/components/app/role-editor.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head>
	<title>New role · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">New role</h1>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the roles.manage permission to manage roles.</p>
{:else if data.error || !data.catalogue}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the permissions: {data.error}</AlertDescription>
	</Alert>
{:else}
	<RoleEditor role={null} catalogue={data.catalogue} />
{/if}
