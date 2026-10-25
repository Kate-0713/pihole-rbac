<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidate } from '$app/navigation';
	import BlockingControl from '#lib/components/app/blocking-control.svelte';
	import DnsRestart from '#lib/components/app/dns-restart.svelte';
	import HealthDot from '#lib/components/app/health-dot.svelte';
	import MemberStatus from '#lib/components/app/member-status.svelte';
	import StatTile from '#lib/components/app/stat-tile.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { formatCount, formatPercent } from '#lib/format.js';
	import { can } from '#lib/permissions.js';
	import { whileVisible } from '#lib/poll.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _summaryKey as summaryKey } from './+page.js';
	import type { PageProps } from './$types';

	// How often the dashboard asks again while it is on screen.
	const refreshEvery = 15_000;

	// `data` is what this page's load returned (summary, error, fetchedAt), plus what the layouts above returned
	// (target). It is replaced each time the load runs again.
	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));

	// Runs the load again. The target list is read too, so the health dots in the header follow along.
	async function refresh() {
		await Promise.all([invalidate(summaryKey), targets.refresh().catch(() => {})]);
	}

	// Only while the dashboard shows an instance. Leaving the page, or the tab being hidden, stops it.
	$effect(() => {
		if (!data.target) return;
		return whileVisible(() => void refresh(), refreshEvery);
	});

	let updated = $derived(new Date(data.fetchedAt).toLocaleTimeString());
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Dashboard · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-baseline justify-between gap-2">
	<h1 class="text-xl font-semibold">Dashboard</h1>
	{#if target}
		<p class="text-muted-foreground text-xs" aria-live="off">Updated {updated}</p>
	{/if}
</div>

{#if target && data.target}
	<p class="flex items-center gap-2 text-sm">
		<HealthDot health={target.health} />
		{target.name}
		<span class="text-muted-foreground">· {target.health?.state ?? 'unknown'}</span>
		{#if target.members}
			<span class="text-muted-foreground">· mirrored group of {target.members.length}</span>
		{/if}
	</p>

	{#if data.error}
		<!-- Shown here rather than in the error banner: it goes away on its own once a refresh succeeds. -->
		<Alert variant="destructive">
			<AlertDescription>Couldn't read the dashboard: {data.error}</AlertDescription>
		</Alert>
	{/if}

	{#if data.summary}
		{@const s = data.summary}
		<div class="grid gap-4 md:grid-cols-2">
			<Card.Root>
				<Card.Header><Card.Title>Blocking</Card.Title></Card.Header>
				<Card.Content>
					<BlockingControl
						target={data.target}
						status={s.blocking}
						fetchedAt={data.fetchedAt}
						canToggle={can('blocking.toggle', data.target)}
						onchange={refresh}
					/>
				</Card.Content>
			</Card.Root>

			{#if can('dns.restart', data.target)}
				<Card.Root>
					<Card.Header>
						<Card.Title>DNS resolver</Card.Title>
						<Card.Description>Restart Pi-hole's resolver to pick up changes or clear its cache.</Card.Description>
					</Card.Header>
					<Card.Content>
						<DnsRestart
							target={data.target}
							name={target.members ? `every member of ${target.name}` : target.name}
							onchange={refresh}
						/>
					</Card.Content>
				</Card.Root>
			{/if}
		</div>

		{#if target.members}
			<Card.Root>
				<Card.Header>
					<Card.Title>Members</Card.Title>
					<Card.Description>
						The counters below add up the members that answered. Lists are read from the primary.
					</Card.Description>
				</Card.Header>
				<Card.Content>
					<MemberStatus members={target.members} reads={s.members} />
				</Card.Content>
			</Card.Root>
		{/if}

		<Card.Root>
			<Card.Header>
				<Card.Title>Last 24 hours</Card.Title>
				<Card.Description>From Pi-hole's long-term database.</Card.Description>
			</Card.Header>
			<Card.Content>
				<dl class="grid grid-cols-2 gap-3 sm:grid-cols-4">
					<StatTile label="Queries" value={formatCount(s.last_24h.queries)} />
					<StatTile label="Blocked" value={formatCount(s.last_24h.blocked)} />
					<StatTile label="Blocked share" value={formatPercent(s.last_24h.percent_blocked)} />
					<StatTile label="Clients" value={formatCount(s.last_24h.clients)} />
				</dl>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<Card.Title>Live</Card.Title>
				<Card.Description>What Pi-hole has in memory now.</Card.Description>
			</Card.Header>
			<Card.Content>
				<dl class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
					<StatTile label="Queries" value={formatCount(s.live.queries)} />
					<StatTile
						label="Blocked"
						value={formatCount(s.live.blocked)}
						detail={formatPercent(s.live.percent_blocked)}
					/>
					<StatTile label="Forwarded" value={formatCount(s.live.forwarded)} />
					<StatTile label="Answered from cache" value={formatCount(s.live.cached)} />
					<StatTile
						label="Active clients"
						value={formatCount(s.live.active_clients)}
						detail="of {formatCount(s.live.total_clients)} seen"
					/>
					<StatTile label="Domains on blocklists" value={formatCount(s.live.domains_on_blocklist)} />
				</dl>
			</Card.Content>
		</Card.Root>
	{/if}
{:else}
	<p class="text-muted-foreground text-sm">
		Welcome, {session.user?.username}. You don't have access to any instance yet.
	</p>
{/if}
