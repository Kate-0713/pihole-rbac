<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import TokenCreateDialog from '#lib/components/app/token-create-dialog.svelte';
	import TokenList from '#lib/components/app/token-list.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { grantableCatalogue } from '#lib/tokens.js';
	import { _myTokensKey as myTokensKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let createOpen = $state(false);

	// What the grants name, for the list. A token's grant on something the user no longer holds is shown by ID.
	let catalogue = $derived(data.grantable ? grantableCatalogue(data.grantable) : null);
	const refresh = () => invalidate(myTokensKey);
</script>

<svelte:head>
	<title>API tokens · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center justify-between gap-2">
	<h1 class="text-xl font-semibold">API tokens</h1>
	{#if data.grantable}
		<Button onclick={() => (createOpen = true)}>New token</Button>
	{/if}
</div>
<p class="text-muted-foreground text-sm">
	For scripts and integrations, such as a Home Assistant button or a cron job. A token can use the Pi-hole and audit log
	endpoints with the permissions you give it, while you still hold them. Revoke any you no longer use.
</p>
{#if !data.grantable && !data.error}
	<p class="text-muted-foreground text-sm">You can't make new tokens: that needs the tokens.use permission.</p>
{/if}

{#if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load your tokens: {data.error}</AlertDescription></Alert>
{:else if data.tokens}
	<TokenList tokens={data.tokens} admin={false} {catalogue} onchanged={refresh} />
{/if}

{#if data.grantable}
	<TokenCreateDialog bind:open={createOpen} grantable={data.grantable} totpOn={data.totpOn} ondone={refresh} />
{/if}
