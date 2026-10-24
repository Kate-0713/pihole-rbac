<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import SessionList from '#lib/components/app/session-list.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { _sessionsKey as sessionsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head>
	<title>Sessions · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">Sessions</h1>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">
		You need the sessions.manage permission to see everyone's sessions. Your own are under
		<a class="underline" href="/account/sessions">Your sessions</a>.
	</p>
{:else if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load the sessions: {data.error}</AlertDescription></Alert>
{:else if data.list}
	<p class="text-muted-foreground text-sm">Everyone who is logged in, newest first. Ending a session logs that browser out.</p>
	<SessionList first={data.list} mine={false} onchanged={() => invalidate(sessionsKey)} />
{/if}
