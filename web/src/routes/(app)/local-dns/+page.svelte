<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { invalidate } from '$app/navigation';
	import DeleteLocalDnsDialog from '#lib/components/app/delete-local-dns-dialog.svelte';
	import DriftBadge from '#lib/components/app/drift-badge.svelte';
	import LocalDnsFormDialog from '#lib/components/app/local-dns-form-dialog.svelte';
	import LocalDnsTable from '#lib/components/app/local-dns-table.svelte';
	import MirroredMemberNote from '#lib/components/app/mirrored-member-note.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { canChange, cnameRow, recordRow, writableProblem, type LocalDNSKind, type Row } from '#lib/local-dns.js';
	import { can } from '#lib/permissions.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import { _localDNSKey as localDNSKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let target = $derived(targets.find(data.target));
	let several = $derived(!!data.target?.startsWith('g-'));
	let dns = $derived(data.dns);
	let canEdit = $derived(can('localdns.edit', data.target));
	let editRecords = $derived(canEdit && !!dns && canChange(dns, 'record'));
	let editCNAMEs = $derived(canEdit && !!dns && canChange(dns, 'cname'));

	let records = $derived((dns?.records ?? []).map(recordRow));
	let cnames = $derived((dns?.cnames ?? []).map(cnameRow));
	let problems = $derived((dns?.instances ?? []).map(writableProblem).filter((p): p is string => p !== null));
	let unparsed = $derived([...records, ...cnames].some((r) => r.marks.includes('unparsed')));
	// What a CNAME can point at and get an address: the names this target answers for itself.
	let localNames = $derived(
		[...records.flatMap((r) => [r.name, ...r.extra]), ...cnames.flatMap((c) => [c.name, ...c.extra])].map((n) => n.toLowerCase())
	);

	let formOpen = $state(false);
	let formKind = $state<LocalDNSKind>('record');
	let editing = $state<Row | null>(null);
	let deleteOpen = $state(false);
	let deleting = $state<Row | null>(null);

	const reload = () => invalidate(localDNSKey);

	function add(kind: LocalDNSKind) {
		formKind = kind;
		editing = null;
		formOpen = true;
	}
	function edit(r: Row) {
		formKind = r.kind;
		editing = r;
		formOpen = true;
	}
	function remove(r: Row) {
		deleting = r;
		deleteOpen = true;
	}
</script>

<svelte:head>
	<title>{target ? `${target.name} · ` : ''}Local DNS · pihole-rbac</title>
</svelte:head>

<div class="flex flex-wrap items-center gap-2">
	<h1 class="text-xl font-semibold">Local DNS</h1>
	{#if data.target && dns}<DriftBadge target={data.target} drifted={dns.drifted} />{/if}
</div>

{#if !data.target}
	<p class="text-muted-foreground text-sm">You don't have access to any instance yet.</p>
{:else if !data.allowed}
	<p class="text-muted-foreground text-sm">You can't view the local DNS of {target?.name ?? 'this instance'}.</p>
{:else if data.error || !dns}
	<Alert variant="destructive">
		<AlertDescription>
			<p>Couldn't read the local DNS: {data.error}</p>
			{#if data.primaryDown}
				<p>A mirrored group's records are read from its primary, so they can't be shown until it answers.</p>
			{/if}
		</AlertDescription>
	</Alert>
	<Button variant="outline" size="sm" class="w-fit" onclick={reload}>Try again</Button>
{:else}
	<p class="text-muted-foreground text-sm">
		Names {target?.name ?? 'this instance'} answers for itself, before asking any upstream server: records give a name
		an address, and CNAMEs give a name another name. A change to a CNAME restarts DNS on the Pi-hole for a moment.
	</p>
	{#if canEdit}
		{#each problems as p (p)}
			<Alert><AlertDescription>{p}</AlertDescription></Alert>
		{/each}
	{/if}
	{#if unparsed}
		<Alert>
			<AlertDescription>
				An entry below doesn't parse. While it's there, Pi-hole refuses every new entry of its kind, here and in its own
				admin. Delete it, or fix it in Pi-hole.
			</AlertDescription>
		</Alert>
	{/if}
	{#if canEdit && target}<MirroredMemberNote {target} />{/if}

	<section class="grid gap-2" aria-labelledby="local-dns-records">
		<div class="flex flex-wrap items-center justify-between gap-2">
			<h2 id="local-dns-records" class="font-semibold">Records</h2>
			{#if editRecords}<Button size="sm" onclick={() => add('record')}><PlusIcon /> Add a record</Button>{/if}
		</div>
		<LocalDnsTable kind="record" rows={records} canEdit={editRecords} onedit={edit} ondelete={remove} />
	</section>

	<section class="grid gap-2" aria-labelledby="local-dns-cnames">
		<div class="flex flex-wrap items-center justify-between gap-2">
			<h2 id="local-dns-cnames" class="font-semibold">CNAMEs</h2>
			{#if editCNAMEs}<Button size="sm" onclick={() => add('cname')}><PlusIcon /> Add a CNAME</Button>{/if}
		</div>
		<LocalDnsTable kind="cname" rows={cnames} canEdit={editCNAMEs} onedit={edit} ondelete={remove} />
	</section>

	{#if canEdit && target && data.target}
		<LocalDnsFormDialog
			bind:open={formOpen}
			target={data.target}
			targetName={target.name}
			kind={formKind}
			entry={editing}
			reasonRequired={dns.reason_required}
			{several}
			{localNames}
			onsaved={reload}
		/>
		<DeleteLocalDnsDialog
			bind:open={deleteOpen}
			target={data.target}
			targetName={target.name}
			entry={deleting}
			reasonRequired={dns.reason_required}
			ondeleted={reload}
		/>
	{/if}
{/if}
