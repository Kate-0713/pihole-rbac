<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import { invalidate } from '$app/navigation';
	import { api, unwrap } from '#lib/api/client.js';
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
		summary,
		type Difference
	} from '#lib/drift.js';
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
		<Button variant="outline" size="sm" onclick={checkNow} disabled={checking}>
			<RefreshCwIcon class={checking ? 'animate-spin' : ''} />
			{checking ? 'Checking…' : 'Check now'}
		</Button>
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
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			</section>
		{/if}
	{/if}
{/if}
