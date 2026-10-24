<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import SessionList from '#lib/components/app/session-list.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { _mySessionsKey as mySessionsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head>
	<title>Your sessions · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">Your sessions</h1>
<p class="text-muted-foreground text-sm">
	Where you are logged in. End any you don't recognise, and change your password if you didn't start them.
</p>

{#if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load your sessions: {data.error}</AlertDescription></Alert>
{:else if data.list}
	<SessionList first={data.list} mine={true} onchanged={() => invalidate(mySessionsKey)} />
{/if}
