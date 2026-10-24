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
	<title>{data.role ? `${data.role.name} · ` : ''}Roles · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">{data.role ? `Role ${data.role.name}` : 'Role'}</h1>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the roles.manage permission to manage roles.</p>
{:else if data.error || !data.role || !data.catalogue}
	<Alert variant="destructive">
		<AlertDescription>Couldn't load the role: {data.error}</AlertDescription>
	</Alert>
{:else}
	<!-- SvelteKit keeps the same page component when the URL moves from one role to another, and only changes `data`.
	     {#key} throws the editor away and makes a new one whenever the role's ID changes, so the form starts afresh
	     from the new role instead of keeping the last one's edits. -->
	{#key data.role.id}
		<RoleEditor role={data.role} catalogue={data.catalogue} />
	{/key}
{/if}
