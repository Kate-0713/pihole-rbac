<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import DownloadIcon from '@lucide/svelte/icons/download';
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import XIcon from '@lucide/svelte/icons/x';
	import { goto, invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import {
		apiQuery,
		auditURL,
		exportHref,
		filtersActive,
		fromLocalInput,
		maxTarget,
		maxUser,
		parseActions,
		timeProblem,
		toLocalInput,
		type AuditEntry,
		type AuditFilters
	} from '#lib/audit.js';
	import AuditTable from '#lib/components/app/audit-table.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { _auditKey as auditKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	// The form's fields, copied from the URL's filters whenever they change (applying the form, clicking a value in the
	// table, Back), so the form always shows what the table is filtered by. The instance filter has no field: it is set
	// by clicking an instance in the table, and shown as a badge that removes it.
	let user = $state('');
	let actions = $state('');
	let target = $state('');
	let result = $state('');
	let from = $state('');
	let to = $state('');
	$effect(() => {
		user = data.filters.user;
		actions = data.filters.actions.join(', ');
		target = data.filters.target;
		result = data.filters.result;
		from = toLocalInput(data.filters.from);
		to = toLocalInput(data.filters.to);
	});

	let parsed = $derived(parseActions(actions));
	let rangeProblem = $derived(timeProblem(fromLocalInput(from), fromLocalInput(to)));
	let active = $derived(filtersActive(data.filters));

	// The pages read with "Show more", after the first. They start again whenever the first page changes.
	let more = $state<AuditEntry[]>([]);
	let cursor = $state<string | undefined>(undefined);
	$effect(() => {
		more = [];
		cursor = data.list?.next_cursor;
	});
	let entries = $derived([...(data.list?.entries ?? []), ...more]);
	let loading = $state(false);
	let refreshing = $state(false);

	const resultLabels: Record<string, string> = { '': 'Any result', success: 'Succeeded', failure: 'Failed' };

	// Applying the form is a navigation to the filtered URL; load then reads the first page again. reset: false keeps
	// the focus and scroll position, as the form is still on screen.
	function apply(event: SubmitEvent) {
		event.preventDefault();
		if (parsed.problem || rangeProblem) return;
		const f: AuditFilters = {
			user: user.trim(),
			actions: parsed.actions,
			target: target.trim(),
			instanceId: data.filters.instanceId,
			result: result === 'success' || result === 'failure' ? result : '',
			from: fromLocalInput(from),
			to: fromLocalInput(to)
		};
		void goto(auditURL(f), { reset: false });
	}

	const filterHref = (change: Partial<AuditFilters>) => auditURL({ ...data.filters, ...change });

	async function showMore() {
		if (!cursor) return;
		loading = true;
		try {
			const page = await unwrap(api.GET('/api/v1/audit', { params: { query: { ...apiQuery(data.filters), cursor } } }));
			more = [...more, ...page.entries];
			cursor = page.next_cursor;
		} catch (e) {
			notices.error(e, "Couldn't read more entries");
		} finally {
			loading = false;
		}
	}

	async function refresh() {
		refreshing = true;
		try {
			await invalidate(auditKey);
		} finally {
			refreshing = false;
		}
	}

	// The instance a filter names, by the name its entries carry.
	let instanceName = $derived(
		data.filters.instanceId === null ? '' : (entries.find((e) => e.instance_id === data.filters.instanceId)?.instance_name ?? `#${data.filters.instanceId}`)
	);
</script>

<svelte:head>
	<title>Audit log · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-start justify-between gap-2">
	<div class="grid gap-1">
		<h1 class="text-xl font-semibold">Audit log</h1>
		<p class="text-muted-foreground text-sm">Every change, login and refused request, newest first.</p>
	</div>
	{#if data.allowed}
		<div class="flex flex-wrap gap-2">
			<Button variant="outline" size="sm" onclick={refresh} disabled={refreshing}>
				<RefreshCwIcon class={refreshing ? 'animate-spin' : ''} />
				Refresh
			</Button>
			<!-- A plain download link: the browser saves the file the server names. -->
			<Button variant="outline" size="sm" href={exportHref(data.filters)} download>
				<DownloadIcon />
				Export CSV
			</Button>
		</div>
	{/if}
</div>

{#if !data.allowed}
	<p class="text-muted-foreground text-sm">You need the audit.view permission to read the audit log.</p>
{:else}
	<form class="grid gap-3" onsubmit={apply} role="search" aria-label="Filter the audit log">
		<div class="flex flex-wrap items-start gap-2">
			<div class="grid min-w-36 flex-1 gap-1">
				<label for="audit-user" class="text-muted-foreground text-xs">User</label>
				<Input id="audit-user" bind:value={user} maxlength={maxUser} autocomplete="off" spellcheck={false} />
			</div>
			<div class="grid min-w-48 flex-1 gap-1">
				<label for="audit-action" class="text-muted-foreground text-xs">Actions</label>
				<Input
					id="audit-action"
					bind:value={actions}
					placeholder="e.g. domain_add, login"
					autocomplete="off"
					spellcheck={false}
					aria-invalid={parsed.problem !== null}
					aria-describedby={parsed.problem ? 'audit-action-problem' : undefined}
				/>
			</div>
			<div class="grid min-w-36 flex-1 gap-1">
				<label for="audit-target" class="text-muted-foreground text-xs">Target</label>
				<Input
					id="audit-target"
					bind:value={target}
					maxlength={maxTarget}
					placeholder="e.g. i-1, user:alice"
					autocomplete="off"
					spellcheck={false}
				/>
			</div>
			<div class="grid gap-1">
				<span id="audit-result-label" class="text-muted-foreground text-xs">Result</span>
				<Select.Root type="single" bind:value={result}>
					<Select.Trigger class="w-36" aria-labelledby="audit-result-label">{resultLabels[result]}</Select.Trigger>
					<Select.Content>
						{#each Object.entries(resultLabels) as [value, label] (value)}
							<Select.Item {value} {label}>{label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
		</div>
		<div class="flex flex-wrap items-end gap-2">
			<div class="grid gap-1">
				<label for="audit-from" class="text-muted-foreground text-xs">From</label>
				<Input id="audit-from" type="datetime-local" bind:value={from} class="w-52" />
			</div>
			<div class="grid gap-1">
				<label for="audit-to" class="text-muted-foreground text-xs">Until</label>
				<Input id="audit-to" type="datetime-local" bind:value={to} class="w-52" aria-invalid={rangeProblem !== null} />
			</div>
			<Button type="submit" disabled={parsed.problem !== null || rangeProblem !== null}>Apply</Button>
			{#if active}
				<Button variant="ghost" href="/admin/audit">Clear filters</Button>
			{/if}
		</div>
		{#if parsed.problem}
			<p id="audit-action-problem" class="text-destructive text-sm">{parsed.problem}</p>
		{/if}
		{#if rangeProblem}
			<p class="text-destructive text-sm">{rangeProblem}</p>
		{/if}
		{#if data.filters.instanceId !== null}
			<div class="flex items-center gap-2 text-sm">
				<span class="text-muted-foreground">Only entries about</span>
				<Badge variant="secondary">
					{instanceName}
					<a href={filterHref({ instanceId: null })} class="ml-1" aria-label="Stop filtering by instance {instanceName}">
						<XIcon class="size-3" />
					</a>
				</Badge>
			</div>
		{/if}
	</form>

	{#if data.error}
		<Alert variant="destructive"><AlertDescription>Couldn't read the audit log: {data.error}</AlertDescription></Alert>
		<Button variant="outline" size="sm" class="w-fit" onclick={refresh}>Try again</Button>
	{:else}
		<AuditTable {entries} {filterHref} empty={active ? 'No entries match these filters.' : 'The audit log is empty.'} />
		<div class="flex flex-wrap items-center gap-3">
			{#if cursor}
				<Button variant="outline" size="sm" onclick={showMore} disabled={loading}>{loading ? 'Reading…' : 'Show more'}</Button>
			{/if}
			<p class="text-muted-foreground text-xs">
				Times are in your browser's time zone. The export holds the newest 50,000 entries that match the filters.
			</p>
		</div>
	{/if}
{/if}
