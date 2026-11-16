<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import CellText from '#lib/components/app/cell-text.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { canMakeStatic, expiryText, type DHCPLease, type DHCPStaticLease } from '#lib/dhcp.js';

	// The leases Pi-hole has handed out, from dnsmasq's lease file. A plain table with a search box, as for local DNS.
	// `statics` are the static leases of the same instance (for hiding Make static on a lease that is one already);
	// the actions only appear when the page passes the handlers, which it does for one instance the user may change.
	let {
		leases,
		statics,
		showInstance,
		onstatic,
		ondelete
	}: {
		leases: DHCPLease[];
		// The static leases by instance ID.
		statics: Map<number, DHCPStaticLease[]>;
		// Through a mirrored group, each row names its instance.
		showInstance: boolean;
		onstatic?: (l: DHCPLease) => void;
		ondelete?: (l: DHCPLease) => void;
	} = $props();

	let search = $state('');
	// Read once per render of the table, not per row.
	const now = Date.now() / 1000;

	let shown = $derived.by(() => {
		const q = search.trim().toLowerCase();
		const match = (l: DHCPLease) =>
			q === '' || [l.ip, l.hwaddr ?? '', l.name ?? '', l.client_id ?? '', l.instance].some((s) => s.toLowerCase().includes(q));
		return leases.filter(match);
	});
	let actions = $derived(!!onstatic || !!ondelete);
	let cols = $derived(4 + (showInstance ? 1 : 0) + (actions ? 1 : 0));
</script>

<div class="flex flex-wrap items-end gap-2">
	<div class="grid min-w-48 flex-1 gap-1">
		<label for="dhcp-leases-search" class="text-muted-foreground text-xs">Search leases by address, MAC or name</label>
		<Input id="dhcp-leases-search" type="search" bind:value={search} autocomplete="off" />
	</div>
</div>
<p class="text-muted-foreground text-xs" aria-live="polite">
	{#if search.trim() !== ''}Showing {shown.length} of {leases.length} leases{:else}{leases.length} leases{/if}
</p>

<div class="overflow-x-auto rounded-lg border">
	<Table.Root aria-label="Leases">
		<Table.Header>
			<Table.Row>
				{#if showInstance}<Table.Head>Pi-hole</Table.Head>{/if}
				<Table.Head>Address</Table.Head>
				<Table.Head>Hardware address</Table.Head>
				<Table.Head>Name</Table.Head>
				<Table.Head>Expires</Table.Head>
				{#if actions}<Table.Head><span class="sr-only">Actions</span></Table.Head>{/if}
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each shown as l (`${l.instance_id} ${l.ip}`)}
				<Table.Row data-lease={l.ip}>
					{#if showInstance}<Table.Cell class="text-sm">{l.instance}</Table.Cell>{/if}
					<Table.Cell class="font-mono text-sm">{l.ip}</Table.Cell>
					<Table.Cell>
						<CellText>
							{#if l.hwaddr}
								<span class="font-mono text-sm">{l.hwaddr}</span>
								{#if l.ipv6}<Badge variant="outline" title="IPv6 leases show an identifier where IPv4 ones show a MAC">IPv6</Badge>{/if}
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</CellText>
					</Table.Cell>
					<Table.Cell class="text-sm"><CellText>{l.name ?? '—'}</CellText></Table.Cell>
					<Table.Cell class="text-muted-foreground text-sm whitespace-nowrap">{expiryText(l.expires, now)}</Table.Cell>
					{#if actions}
						<Table.Cell class="text-right whitespace-nowrap">
							{#if onstatic && canMakeStatic(l, statics.get(l.instance_id) ?? [])}
								<Button variant="ghost" size="sm" onclick={() => onstatic(l)} aria-label="Make {l.ip} static">Make static</Button>
							{/if}
							{#if ondelete}
								<Button variant="ghost" size="sm" class="text-destructive" onclick={() => ondelete(l)} aria-label="Delete the lease for {l.ip}"
									>Delete</Button
								>
							{/if}
						</Table.Cell>
					{/if}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={cols} class="text-muted-foreground py-6 text-center">
						{search.trim() !== '' ? 'Nothing matches.' : 'No leases.'}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
