<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { invalidate } from '$app/navigation';
	import SessionList from '#lib/components/app/session-list.svelte';
	import TokenList from '#lib/components/app/token-list.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { _sessionsKey as sessionsKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let tab = $state('sessions');
	let activeTokens = $derived((data.tokens ?? []).filter((t) => t.state === 'active').length);

	const tabClass =
		'text-muted-foreground data-[state=active]:text-foreground data-[state=active]:border-primary -mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium';
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
{:else if data.list && data.tokens}
	<!-- bits-ui's Tabs, unstyled, as on the DHCP page: bind:value keeps the chosen tab in $state, so it stays put when
	     the data is read again after a change. -->
	<Tabs.Root bind:value={tab} class="grid gap-4">
		<Tabs.List class="flex border-b" aria-label="Sessions and API tokens">
			<Tabs.Trigger value="sessions" class={tabClass}>Sessions</Tabs.Trigger>
			<Tabs.Trigger value="tokens" class={tabClass}>API tokens ({activeTokens})</Tabs.Trigger>
		</Tabs.List>
		<Tabs.Content value="sessions" class="grid gap-2">
			<p class="text-muted-foreground text-sm">Everyone who is logged in, newest first. Ending a session logs that browser out.</p>
			<SessionList first={data.list} mine={false} onchanged={() => invalidate(sessionsKey)} />
		</Tabs.Content>
		<Tabs.Content value="tokens" class="grid gap-2">
			<p class="text-muted-foreground text-sm">
				Everyone's API tokens, by owner. Revoking one stops whatever uses it at once. Revoked and expired tokens are listed for
				30 days.
			</p>
			<TokenList tokens={data.tokens} admin={true} catalogue={data.catalogue} onchanged={() => invalidate(sessionsKey)} />
		</Tabs.Content>
	</Tabs.Root>
{/if}
