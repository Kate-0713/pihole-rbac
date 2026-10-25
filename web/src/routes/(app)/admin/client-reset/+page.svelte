<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import ClientResetHistory from '#lib/components/app/client-reset-history.svelte';
	import ClientResetRulesCard from '#lib/components/app/client-reset-rules-card.svelte';
	import ClientResetScheduleCard from '#lib/components/app/client-reset-schedule-card.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import type { Run } from '#lib/clientreset.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { _resetKey as resetKey } from './+page.js';
	import type { PageProps } from './$types';

	// `data` is what load returned; it changes whenever load runs again, and everything derived from it follows.
	let { data }: PageProps = $props();

	// The pages read with "Show more", after the first. They start again whenever the first page changes.
	let more = $state<Run[]>([]);
	let cursor = $state<string | undefined>(undefined);
	$effect(() => {
		more = [];
		cursor = data.runs?.next_cursor;
	});
	let runs = $derived([...(data.runs?.runs ?? []), ...more]);
	let loading = $state(false);
	let refreshing = $state(false);

	const reload = () => invalidate(resetKey);

	async function refresh() {
		refreshing = true;
		try {
			await reload();
		} finally {
			refreshing = false;
		}
	}

	async function showMore() {
		if (!cursor) return;
		loading = true;
		try {
			const page = await unwrap(api.GET('/api/v1/client-reset/runs', { params: { query: { cursor } } }));
			more = [...more, ...page.runs];
			cursor = page.next_cursor;
		} catch (e) {
			notices.error(e, "Couldn't read more runs");
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Client reset · pihole-rbac</title>
</svelte:head>

<div class="grid gap-1">
	<h1 class="text-xl font-semibold">Client reset</h1>
	<p class="text-muted-foreground text-sm">
		Puts clients back in their usual Pi-hole groups after they've been moved for testing, picked out by the start of
		their comment. Runs are started from an instance's or group's dashboard, or daily on the schedule.
	</p>
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the settings.manage permission to manage client reset.</p>
{:else if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load client reset: {data.error}</AlertDescription></Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	{#if data.rules}
		<ClientResetRulesCard settings={data.rules} onsaved={reload} />
	{/if}
	{#if data.general}
		<ClientResetScheduleCard settings={data.general} onsaved={reload} />
	{/if}
	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Runs</h2></Card.Title>
			<Card.Description>Every run, newest first. Kept as long as the audit log keeps its entries.</Card.Description>
			<Card.Action>
				<Button variant="outline" size="sm" onclick={refresh} disabled={refreshing}><RefreshCwIcon /> Refresh</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content class="grid gap-3">
			<ClientResetHistory {runs} empty="No runs yet." />
			{#if cursor}
				<Button variant="outline" size="sm" class="w-fit" onclick={showMore} disabled={loading}>{loading ? 'Reading…' : 'Show more'}</Button>
			{/if}
		</Card.Content>
	</Card.Root>
{/if}
