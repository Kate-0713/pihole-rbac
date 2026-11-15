<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import Columns3Icon from '@lucide/svelte/icons/columns-3';
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import { goto, invalidate } from '$app/navigation';
	import { page } from '$app/state';
	import QueryPager from '#lib/components/app/query-pager.svelte';
	import QueryTable from '#lib/components/app/query-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		describePage,
		filterProblem,
		filterURL,
		forgetSnapshot,
		fromLocalInput,
		hideableColumns,
		isFiltered,
		maxFilterChars,
		mergedDepth,
		noFilters,
		pageSizes,
		queryResults,
		queryTypes,
		readHiddenColumns,
		saveHiddenColumns,
		statuses,
		timeRanges,
		toLocalInput,
		type ColumnId,
		type PageSize,
		type QueryFilters,
		type TimeRange
	} from '#lib/queries.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _queriesKey as queriesKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let isGroup = $derived(target?.kind === 'group');
	let log = $derived(data.log);
	// For a mirrored group: the members whose queries aren't in the log, because they didn't answer.
	let missing = $derived((log?.members ?? []).filter((m) => m.status !== 'ok'));
	let pickedMember = $derived(target?.members?.find((m) => m.instance_id === data.filters.member));

	// The form's fields, copied from the URL's filters whenever they change (applying a filter, clicking a domain in
	// the table, Back), so the form always shows what the log is filtered by. Selects can't hold an empty value, so
	// "any" stands for no filter there.
	const any = 'any';
	let domain = $state('');
	let client = $state('');
	let range = $state<string>(any);
	let from = $state('');
	let until = $state('');
	let status = $state<string>(any);
	let qtype = $state<string>(any);
	let result = $state<string>(any);
	let member = $state<string>(any);
	$effect(() => {
		const f = data.filters;
		domain = f.domain;
		client = f.client;
		range = f.range || any;
		from = toLocalInput(f.from);
		until = toLocalInput(f.until);
		status = f.status || any;
		qtype = f.type || any;
		result = f.result || any;
		member = f.member === null ? any : String(f.member);
	});

	let domainProblem = $derived(filterProblem('domain', domain));
	let clientProblem = $derived(filterProblem('client', client));
	let rangeProblem = $derived(
		range === 'custom' && from && until && fromLocalInput(until) <= fromLocalInput(from)
			? 'The end must be after the start.'
			: range === 'custom' && !from && !until
				? 'Give a start, an end, or both.'
				: null
	);
	let filtered = $derived(isFiltered(data.filters));
	let refreshing = $state(false);

	// Applying the filters is a navigation to the filtered URL, back at page 1; load then reads the log again.
	// reset: false keeps the focus and scroll position, as the form is still on screen.
	function apply(event: SubmitEvent) {
		event.preventDefault();
		if (domainProblem || clientProblem || rangeProblem) return;
		const changes: Partial<QueryFilters> = {
			domain,
			client,
			range: (range === any ? '' : range) as TimeRange,
			status: (status === any ? '' : status) as QueryFilters['status'],
			type: (qtype === any ? '' : qtype) as QueryFilters['type'],
			result: (result === any ? '' : result) as QueryFilters['result'],
			member: member === any ? null : Number(member)
		};
		if (range === 'custom') {
			changes.from = fromLocalInput(from);
			changes.until = fromLocalInput(until);
		}
		void goto(filterURL(page.url, changes), { reset: false });
	}

	// Refresh starts the search again: the snapshot is dropped, so new queries show and the page count is current.
	async function refresh() {
		refreshing = true;
		forgetSnapshot();
		try {
			await invalidate(queriesKey);
		} finally {
			refreshing = false;
		}
	}

	const filterHref = (by: 'domain' | 'client', value: string) => filterURL(page.url, { [by]: value });
	const pageHref = (p: number) => filterURL(page.url, { page: p });
	let clearHref = $derived(
		filterURL(page.url, { ...noFilters, pageSize: data.filters.pageSize, member: data.filters.member })
	);

	function setPageSize(value: string) {
		void goto(filterURL(page.url, { pageSize: Number(value) as PageSize }), { reset: false });
	}

	// The columns shown, remembered in this browser only.
	function storage(): Storage | undefined {
		try {
			return typeof localStorage === 'undefined' ? undefined : localStorage;
		} catch {
			return undefined;
		}
	}
	let visibility = $state<Record<string, boolean>>(readHiddenColumns(storage()));
	let columnChoices = $derived(
		(Object.keys(hideableColumns) as ColumnId[]).filter((id) => id !== 'instance' || isGroup)
	);
	function toggleColumn(id: ColumnId, shown: boolean) {
		const next = { ...visibility };
		if (shown) delete next[id];
		else next[id] = false;
		// At least one column stays.
		if (columnChoices.every((c) => next[c] === false)) return;
		visibility = next;
		saveHiddenColumns(storage(), next);
	}

	let emptyText = $derived(
		log && log.page > 1 && log.page > log.pages
			? 'There are no queries on this page.'
			: filtered
				? 'No queries match.'
				: 'The query log is empty.'
	);
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Query log · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-start justify-between gap-2">
	<div class="grid gap-1">
		<h1 class="text-xl font-semibold">Query log</h1>
		<p class="text-muted-foreground text-sm">
			{isGroup && !pickedMember
				? `The DNS queries the members of ${target?.name} answered, merged, newest first.`
				: pickedMember
					? `The DNS queries ${pickedMember.name} answered, newest first.`
					: 'The DNS queries this Pi-hole answered, newest first.'}
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
	<!-- Every link here (pages, filters, Clear filters) loads a page of the log from Pi-hole, which can be a large or
	long-term read, so it is preloaded only on a press, not on hover as elsewhere. display: contents keeps the
	layout as if the wrapper weren't there. -->
	<div class="contents" data-sveltekit-preload-data="tap">
		<form class="flex flex-wrap items-start gap-2" onsubmit={apply} role="search" aria-label="Filter the query log">
			<div class="grid min-w-40 flex-1 gap-1">
				<label for="query-domain" class="text-muted-foreground text-xs">Domain contains</label>
				<Input
					id="query-domain"
					bind:value={domain}
					maxlength={maxFilterChars}
					autocomplete="off"
					spellcheck={false}
					aria-invalid={domainProblem ? 'true' : undefined}
					aria-describedby={domainProblem ? 'query-domain-problem' : undefined}
				/>
				{#if domainProblem}<span id="query-domain-problem" class="text-destructive text-xs">{domainProblem}</span>{/if}
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
					aria-invalid={clientProblem ? 'true' : undefined}
					aria-describedby={clientProblem ? 'query-client-problem' : undefined}
				/>
				{#if clientProblem}<span id="query-client-problem" class="text-destructive text-xs">{clientProblem}</span>{/if}
			</div>
			<div class="grid gap-1">
				<span id="query-range-label" class="text-muted-foreground text-xs">When</span>
				<Select.Root type="single" bind:value={range}>
					<Select.Trigger class="w-40" aria-labelledby="query-range-label">{timeRanges[range === any ? '' : (range as TimeRange)]}</Select.Trigger>
					<Select.Content>
						{#each Object.entries(timeRanges) as [value, label] (value)}
							<Select.Item value={value || any} {label}>{label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			{#if range === 'custom'}
				<div class="grid gap-1">
					<label for="query-from" class="text-muted-foreground text-xs">From</label>
					<Input id="query-from" type="datetime-local" bind:value={from} class="w-52" />
				</div>
				<div class="grid gap-1">
					<label for="query-until" class="text-muted-foreground text-xs">Until</label>
					<Input
						id="query-until"
						type="datetime-local"
						bind:value={until}
						class="w-52"
						aria-invalid={rangeProblem ? 'true' : undefined}
						aria-describedby={rangeProblem ? 'query-range-problem' : undefined}
					/>
					{#if rangeProblem}<span id="query-range-problem" class="text-destructive text-xs">{rangeProblem}</span>{/if}
				</div>
			{/if}
			<div class="grid gap-1">
				<span id="query-result-label" class="text-muted-foreground text-xs">Result</span>
				<Select.Root type="single" bind:value={result}>
					<Select.Trigger class="w-36" aria-labelledby="query-result-label"
						>{result === any ? 'All results' : queryResults[result as keyof typeof queryResults]}</Select.Trigger
					>
					<Select.Content>
						<Select.Item value={any} label="All results">All results</Select.Item>
						{#each Object.entries(queryResults) as [value, label] (value)}
							<Select.Item {value} {label}>{label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			<div class="grid gap-1">
				<span id="query-status-label" class="text-muted-foreground text-xs">Status</span>
				<Select.Root type="single" bind:value={status}>
					<Select.Trigger class="w-52" aria-labelledby="query-status-label"
						>{status === any ? 'Any status' : statuses[status as keyof typeof statuses].label}</Select.Trigger
					>
					<Select.Content>
						<Select.Item value={any} label="Any status">Any status</Select.Item>
						{#each Object.entries(statuses) as [value, s] (value)}
							<Select.Item {value} label={s.label}>{s.label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			<div class="grid gap-1">
				<span id="query-type-label" class="text-muted-foreground text-xs">Type</span>
				<Select.Root type="single" bind:value={qtype}>
					<Select.Trigger class="w-28" aria-labelledby="query-type-label">{qtype === any ? 'Any type' : qtype}</Select.Trigger>
					<Select.Content>
						<Select.Item value={any} label="Any type">Any type</Select.Item>
						{#each queryTypes as t (t)}
							<Select.Item value={t} label={t === 'OTHER' ? 'Other types' : t}>{t === 'OTHER' ? 'Other types' : t}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			{#if isGroup && target?.members}
				<div class="grid gap-1">
					<span id="query-member-label" class="text-muted-foreground text-xs">Member</span>
					<Select.Root type="single" bind:value={member}>
						<Select.Trigger class="w-40" aria-labelledby="query-member-label"
							>{target.members.find((m) => String(m.instance_id) === member)?.name ?? 'All members'}</Select.Trigger
						>
						<Select.Content>
							<Select.Item value={any} label="All members">All members</Select.Item>
							{#each target.members as m (m.instance_id)}
								<Select.Item value={String(m.instance_id)} label={m.name}>{m.name}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
				</div>
			{/if}
			<div class="grid gap-1">
				<span class="text-xs" aria-hidden="true">&nbsp;</span>
				<div class="flex gap-2">
					<Button type="submit">Apply</Button>
					{#if filtered}
						<Button variant="ghost" href={clearHref}>Clear filters</Button>
					{/if}
				</div>
			</div>
		</form>

		{#if data.error}
			<Alert variant="destructive">
				<AlertDescription>Couldn't read the query log: {data.error}</AlertDescription>
			</Alert>
			<Button variant="outline" size="sm" class="w-fit" onclick={refresh}>Try again</Button>
		{:else if log}
			{#if missing.length > 0}
				<Alert>
					<AlertDescription>
						Not included, because {missing.length === 1 ? 'it' : 'they'} didn't answer: {missing
							.map((m) => (m.error ? `${m.instance} (${m.error.message})` : m.instance))
							.join(', ')}
					</AlertDescription>
				</Alert>
			{/if}
			{#if log.capped}
				<Alert>
					<AlertDescription>
						Only the newest {mergedDepth.toLocaleString('en')} queries of the merged log can be paged through. Narrow the
						time range, or pick a member to page through all of its queries.
					</AlertDescription>
				</Alert>
			{/if}

			<div class="flex flex-wrap items-center justify-between gap-2">
				<p class="text-muted-foreground text-xs" aria-live="polite">
					{describePage(log.total, log.page, log.pages)}{log.source === 'disk'
						? ' · from the long-term database'
						: log.source === 'mixed'
							? ' · some members from the long-term database'
							: ''}
				</p>
				<div class="flex items-center gap-2">
					<Select.Root type="single" value={String(data.filters.pageSize)} onValueChange={setPageSize}>
						<Select.Trigger class="w-32" aria-label="Per page">{data.filters.pageSize} per page</Select.Trigger>
						<Select.Content>
							{#each pageSizes as n (n)}
								<Select.Item value={String(n)} label="{n} per page">{n} per page</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
					<DropdownMenu.Root>
						<DropdownMenu.Trigger>
							{#snippet child({ props })}
								<Button {...props} variant="outline" size="sm"><Columns3Icon />Columns</Button>
							{/snippet}
						</DropdownMenu.Trigger>
						<DropdownMenu.Content align="end">
							<DropdownMenu.Label class="text-muted-foreground text-xs font-normal">Columns shown</DropdownMenu.Label>
							{#each columnChoices as id (id)}
								<DropdownMenu.CheckboxItem
									checked={visibility[id] !== false}
									onCheckedChange={(shown) => toggleColumn(id, shown)}>{hideableColumns[id]}</DropdownMenu.CheckboxItem
								>
							{/each}
						</DropdownMenu.Content>
					</DropdownMenu.Root>
				</div>
			</div>

			<QueryPager page={log.page} pages={log.pages} capped={log.capped} href={pageHref} />
			<QueryTable showInstance={isGroup && !pickedMember} queries={log.queries} {filterHref} {visibility} empty={emptyText} />
		{/if}
	</div>
{/if}
