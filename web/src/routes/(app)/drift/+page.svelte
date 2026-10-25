<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
	import ReconcileAllDialog from '#lib/components/app/reconcile-all-dialog.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import {
		clientChanges,
		differenceHint,
		differenceLabel,
		domainChanges,
		groupChanges,
		reconcileKey,
		reconcileSummary,
		summary,
		type Difference,
		type ReconcileResult
	} from '#lib/drift.js';
	import { can } from '#lib/permissions.js';
	import { formatDateTime } from '#lib/format.js';
	import { whileVisible } from '#lib/poll.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _driftKey as driftKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let report = $derived(data.report);

	// Checks run on the server every few minutes and soon after writes; the page reads the latest report every 30
	// seconds while it's on screen, and the target list with it, for the picker's drifted mark.
	$effect(() => {
		if (!data.groupId) return;
		return whileVisible(() => void Promise.all([invalidate(driftKey), targets.refresh().catch(() => {})]), 30_000);
	});

	let checking = $state(false);
	async function checkNow() {
		if (!data.groupId) return;
		checking = true;
		try {
			await unwrap(api.POST('/api/v1/instance-groups/{id}/drift/check', { params: { path: { id: data.groupId } } }));
			await Promise.all([invalidate(driftKey), targets.refresh().catch(() => {})]);
		} catch (e) {
			notices.error(e, "Couldn't check the group");
		} finally {
			checking = false;
		}
	}

	// Reconciling needs drift.reconcile on the group; the server checks it again.
	let canReconcile = $derived(!!data.target && can('drift.reconcile', data.target));
	let reconcileOpen = $state(false);
	// The item being fixed ("domain:<member>:<key>"), or "all", while a reconcile runs.
	let reconciling = $state<string | null>(null);

	type Body = {
		all?: boolean;
		domains?: { instance_id: number; domain: string; type: 'allow' | 'deny'; kind: 'exact' | 'regex' }[];
		clients?: { instance_id: number; client: string }[];
		groups?: { instance_id: number; name: string }[];
	};

	// reconcile sends the request, reports what happened (a toast for what worked, an error per item that didn't), and
	// reads the page again: the answer's report is already stored on the server.
	async function reconcile(body: Body, key: string) {
		if (!data.groupId) return;
		reconciling = key;
		try {
			const out: ReconcileResult = await unwrap(
				api.POST('/api/v1/instance-groups/{id}/reconcile', { params: { path: { id: data.groupId } }, body })
			);
			for (const m of out.members) {
				if (m.error) notices.error(`${m.error.message} It was left as it was.`, `Couldn't reconcile ${m.instance}`);
			}
			for (const r of out.results) {
				if (r.error) notices.error(r.error.message, `Couldn't reconcile ${reconcileKey(r)} on ${r.instance}`);
			}
			if (out.results.some((r) => r.status === 'ok' && r.action !== 'none') || out.results.every((r) => r.status === 'ok')) {
				notices.success(reconcileSummary(out));
			}
			reconcileOpen = false;
		} catch (e) {
			notices.error(e, "Couldn't reconcile the group");
		} finally {
			reconciling = null;
			await Promise.all([invalidate(driftKey), targets.refresh().catch(() => {})]);
		}
	}

	const tone: Record<Difference, 'destructive' | 'secondary' | 'outline'> = {
		missing: 'destructive',
		extra: 'outline',
		changed: 'secondary'
	};
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Drift · pihole-rbac</title>
</svelte:head>

{#snippet difference(d: Difference)}
	<Badge variant={tone[d]} title={differenceHint[d]}>{differenceLabel[d]}</Badge>
{/snippet}

{#snippet changes(list: string[])}
	{#if list.length > 0}
		<ul class="text-muted-foreground text-xs">
			{#each list as c (c)}<li>{c}</li>{/each}
		</ul>
	{/if}
{/snippet}

{#snippet fix(key: string, what: string, body: Body)}
	<Button
		variant="outline"
		size="sm"
		disabled={reconciling !== null}
		aria-label="Make {what} match the primary"
		onclick={() => reconcile(body, key)}
	>
		{reconciling === key ? 'Fixing…' : 'Fix'}
	</Button>
{/snippet}

{#snippet hidden(what: string, permission: string, n: number)}
	<p class="text-muted-foreground text-sm">
		{n === 1 ? `1 ${what} differs` : `${n} ${what}s differ`}. Seeing which needs {permission} on this group.
	</p>
{/snippet}

<div class="flex flex-wrap items-start justify-between gap-2">
	<div class="grid gap-1">
		<h1 class="text-xl font-semibold">Drift</h1>
		<p class="text-muted-foreground text-sm">
			How each member of a mirrored group differs from its primary, the group's source of truth.
		</p>
	</div>
	{#if report}
		<div class="flex flex-wrap gap-2">
			<Button variant="outline" size="sm" onclick={checkNow} disabled={checking}>
				<RefreshCwIcon class={checking ? 'animate-spin' : ''} />
				{checking ? 'Checking…' : 'Check now'}
			</Button>
			{#if canReconcile && report.state === 'checked' && report.drifted}
				<Button size="sm" onclick={() => (reconcileOpen = true)} disabled={reconciling !== null}>Reconcile all…</Button>
			{/if}
		</div>
	{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if data.groupId === null}
	<p class="text-muted-foreground text-sm">
		Drift is about mirrored groups. Choose a mirrored group in the picker to see how its members differ.
	</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You need drift.view on {target?.name ?? 'this group'} to see its drift.</p>
{:else if data.error}
	<Alert variant="destructive">
		<AlertDescription>Couldn't read the drift report: {data.error}</AlertDescription>
	</Alert>
{:else if report}
	<Card.Root>
		<Card.Header>
			<Card.Title class="flex flex-wrap items-center gap-2">
				<h2>{report.group}</h2>
				{#if report.state === 'checked'}
					<Badge variant={report.drifted ? 'destructive' : 'secondary'}>{report.drifted ? 'Drifted' : 'In sync'}</Badge>
				{/if}
			</Card.Title>
			<Card.Description>
				{summary(report)}
				{#if report.checked_at}Checked {formatDateTime(report.checked_at)}.{/if}
			</Card.Description>
		</Card.Header>
		{#if report.members.length > 0}
			<Card.Content>
				<ul class="grid gap-1.5 text-sm" aria-label="Members checked">
					{#each report.members as m (m.instance_id)}
						<li class="flex flex-wrap items-center gap-x-2">
							<span class="font-medium">{m.instance}</span>
							{#if m.primary}<Badge variant="outline">Primary</Badge>{/if}
							{#if m.error}<span class="text-destructive">· {m.error.message} Its differences are unknown.</span>{/if}
						</li>
					{/each}
				</ul>
			</Card.Content>
		{/if}
	</Card.Root>

	{#if report.state === 'checked' && report.drifted}
		{#if report.counts.domains > 0}
			<section class="grid gap-2" aria-labelledby="drift-domains">
				<h2 id="drift-domains" class="font-semibold">Domain lists</h2>
				{#if report.domains}
					<div class="overflow-x-auto rounded-lg border">
						<Table.Root>
							<Table.Header>
								<Table.Row>
									<Table.Head>Member</Table.Head>
									<Table.Head>Entry</Table.Head>
									<Table.Head>Difference</Table.Head>
									{#if canReconcile}<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>{/if}
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{#each report.domains as d (d.instance_id + d.type + d.kind + d.domain)}
									<Table.Row>
										<Table.Cell>{d.instance}</Table.Cell>
										<Table.Cell>
											<span class="font-mono text-sm break-all">{d.domain}</span>
											<span class="text-muted-foreground block text-xs">{d.type} list, {d.kind}</span>
										</Table.Cell>
										<Table.Cell class="whitespace-normal">
											{@render difference(d.difference)}
											{@render changes(domainChanges(d))}
										</Table.Cell>
										{#if canReconcile}
											{@const key = `domain:${d.instance_id}:${d.type}:${d.kind}:${d.domain}`}
											<Table.Cell>
												{@render fix(
													key,
													`${d.domain} on ${d.instance}`,
													{ domains: [{ instance_id: d.instance_id, domain: d.domain, type: d.type, kind: d.kind }] }
												)}
											</Table.Cell>
										{/if}
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{:else}
					{@render hidden('domain list entry', 'domains.view', report.counts.domains)}
				{/if}
			</section>
		{/if}

		{#if report.counts.clients > 0}
			<section class="grid gap-2" aria-labelledby="drift-clients">
				<h2 id="drift-clients" class="font-semibold">Clients</h2>
				{#if report.clients}
					<div class="overflow-x-auto rounded-lg border">
						<Table.Root>
							<Table.Header>
								<Table.Row>
									<Table.Head>Member</Table.Head>
									<Table.Head>Client</Table.Head>
									<Table.Head>Difference</Table.Head>
									{#if canReconcile}<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>{/if}
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{#each report.clients as c (c.instance_id + c.client)}
									<Table.Row>
										<Table.Cell>{c.instance}</Table.Cell>
										<Table.Cell class="font-mono text-sm break-all">{c.client}</Table.Cell>
										<Table.Cell class="whitespace-normal">
											{@render difference(c.difference)}
											{@render changes(clientChanges(c))}
										</Table.Cell>
										{#if canReconcile}
											<Table.Cell>
												{@render fix(`client:${c.instance_id}:${c.client}`, `${c.client} on ${c.instance}`, {
													clients: [{ instance_id: c.instance_id, client: c.client }]
												})}
											</Table.Cell>
										{/if}
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{:else}
					{@render hidden('client', 'clients.view', report.counts.clients)}
				{/if}
			</section>
		{/if}

		{#if report.groups && report.groups.length > 0}
			<section class="grid gap-2" aria-labelledby="drift-groups">
				<h2 id="drift-groups" class="font-semibold">Pi-hole groups</h2>
				<div class="overflow-x-auto rounded-lg border">
					<Table.Root>
						<Table.Header>
							<Table.Row>
								<Table.Head>Member</Table.Head>
								<Table.Head>Group</Table.Head>
								<Table.Head>Difference</Table.Head>
								{#if canReconcile}<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>{/if}
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{#each report.groups as g (g.instance_id + g.name)}
								<Table.Row>
									<Table.Cell>{g.instance}</Table.Cell>
									<Table.Cell>{g.name}</Table.Cell>
									<Table.Cell class="whitespace-normal">
										{@render difference(g.difference)}
										{@render changes(groupChanges(g))}
									</Table.Cell>
									{#if canReconcile}
										<Table.Cell>
											<!-- A group only a member has is never deleted, so there is nothing to fix. -->
											{#if g.difference !== 'extra'}
												{@render fix(`group:${g.instance_id}:${g.name}`, `the ${g.name} group on ${g.instance}`, {
													groups: [{ instance_id: g.instance_id, name: g.name }]
												})}
											{:else}
												<span class="text-muted-foreground text-xs">Kept</span>
											{/if}
										</Table.Cell>
									{/if}
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			</section>
		{/if}
	{/if}
	{#if canReconcile}
		<ReconcileAllDialog
			bind:open={reconcileOpen}
			{report}
			busy={reconciling === 'all'}
			onconfirm={() => reconcile({ all: true }, 'all')}
		/>
	{/if}
{/if}
