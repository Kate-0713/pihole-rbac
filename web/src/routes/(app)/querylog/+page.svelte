<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import { goto, invalidate } from '$app/navigation';
	import { page } from '$app/state';
	import QueryTable from '#lib/components/app/query-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { defaultLength, filterURL, maxFilterChars, queryLengths } from '#lib/queries.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _queriesKey as queriesKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	// For a mirrored group: the members whose queries aren't in the log, because they didn't answer.
	let missing = $derived((data.members ?? []).filter((m) => m.status !== 'ok'));

	// The form's fields, copied from the URL's filters whenever they change (applying a filter, clicking a domain in
	// the table, Back), so the form always shows what the table is filtered by.
	let domain = $state('');
	let client = $state('');
	let length = $state(String(defaultLength));
	$effect(() => {
		domain = data.filters.domain;
		client = data.filters.client;
		length = String(data.filters.length);
	});

	let filtered = $derived(data.filters.domain !== '' || data.filters.client !== '');
	let refreshing = $state(false);

	// Applying the filters is a navigation to the filtered URL; load then reads the log again. reset: false keeps the
	// focus and scroll position, as the form is still on screen.
	function apply(event: SubmitEvent) {
		event.preventDefault();
		void goto(filterURL(page.url, { domain, client, length: Number(length) }), { reset: false });
	}

	async function refresh() {
		refreshing = true;
		try {
			await invalidate(queriesKey);
		} finally {
			refreshing = false;
		}
	}

	const filterHref = (by: 'domain' | 'client', value: string) => filterURL(page.url, { [by]: value });
	let clearHref = $derived(filterURL(page.url, { domain: '', client: '' }));
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Query log · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-start justify-between gap-2">
	<div class="grid gap-1">
		<h1 class="text-xl font-semibold">Query log</h1>
		<p class="text-muted-foreground text-sm">
			{target?.members
				? `The newest DNS queries the members of ${target.name} answered, merged, newest first.`
				: 'The newest DNS queries this Pi-hole answered, newest first.'}
		</p>
	</div>
	{#if data.allowed && data.target}
		<Button variant="outline" size="sm" onclick={refresh} disabled={refreshing}>
			<RefreshCwIcon class={refreshing ? 'animate-spin' : ''} />
			Refresh
		</Button>
	{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the query log of {target?.name ?? 'this instance'}.</p>
{:else}
	<form class="flex flex-wrap items-end gap-2" onsubmit={apply} role="search" aria-label="Filter the query log">
		<div class="grid min-w-40 flex-1 gap-1">
			<label for="query-domain" class="text-muted-foreground text-xs">Domain contains</label>
			<Input id="query-domain" bind:value={domain} maxlength={maxFilterChars} autocomplete="off" spellcheck={false} />
		</div>
		<div class="grid min-w-40 flex-1 gap-1">
			<label for="query-client" class="text-muted-foreground text-xs">Client contains</label>
			<Input
				id="query-client"
				bind:value={client}
				maxlength={maxFilterChars}
				placeholder="Address or name"
				autocomplete="off"
				spellcheck={false}
			/>
		</div>
		<div class="grid gap-1">
			<span id="query-length-label" class="text-muted-foreground text-xs">Read the newest</span>
			<Select.Root type="single" bind:value={length}>
				<Select.Trigger class="w-32" aria-labelledby="query-length-label">{length} queries</Select.Trigger>
				<Select.Content>
					{#each queryLengths as n (n)}
						<Select.Item value={String(n)} label="{n} queries">{n} queries</Select.Item>
					{/each}
				</Select.Content>
			</Select.Root>
		</div>
		<Button type="submit">Apply</Button>
		{#if filtered}
			<Button variant="ghost" href={clearHref}>Clear filters</Button>
		{/if}
	</form>
	{#if filtered}
		<p class="text-muted-foreground text-xs">
			The filters are applied to the newest {data.filters.length} queries, so fewer may show.
		</p>
	{/if}

	{#if data.error}
		<Alert variant="destructive">
			<AlertDescription>Couldn't read the query log: {data.error}</AlertDescription>
		</Alert>
		<Button variant="outline" size="sm" class="w-fit" onclick={refresh}>Try again</Button>
	{:else}
		{#if missing.length > 0}
			<Alert>
				<AlertDescription>
					Not included, because {missing.length === 1 ? 'it' : 'they'} didn't answer: {missing
						.map((m) => (m.error ? `${m.instance} (${m.error.message})` : m.instance))
						.join(', ')}
				</AlertDescription>
			</Alert>
		{/if}
		<QueryTable
			showInstance={target?.kind === 'group'}
			queries={data.queries}
			{filterHref}
			empty={filtered ? 'No queries match among the newest ' + data.filters.length + '.' : 'The query log is empty.'}
		/>
	{/if}
{/if}
