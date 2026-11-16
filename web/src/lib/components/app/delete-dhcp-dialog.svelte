<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import type { DHCPLease, DHCPStaticLease } from '#lib/dhcp.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';

	// Deleting a lease, or a static lease. A lease isn't blocked by deleting it: the device asks for an address again.
	// A static lease is named by Pi-hole's own string, and every spelling of it is deleted.
	let {
		open = $bindable(false),
		target,
		targetName,
		lease = null,
		staticLease = null,
		ondeleted
	}: {
		open: boolean;
		target: string;
		targetName: string;
		lease?: DHCPLease | null;
		staticLease?: DHCPStaticLease | null;
		ondeleted: () => Promise<void> | void;
	} = $props();

	let busy = $state(false);
	let shown = $derived(lease ? lease.ip : (staticLease?.mac ?? staticLease?.value ?? ''));

	async function remove(event: MouseEvent) {
		// The action would close the dialog at once; it stays open while the request runs.
		event.preventDefault();
		busy = true;
		const text = lease
			? { done: `Lease for ${shown} deleted`, failed: `Couldn't delete the lease for ${shown}` }
			: { done: `Static lease for ${shown} deleted`, failed: `Couldn't delete the static lease for ${shown}` };
		const params = { path: { target } };
		try {
			const results = lease
				? (await unwrap(api.DELETE('/api/v1/targets/{target}/dhcp/leases', { params, body: { ip: lease.ip } }))).results
				: staticLease
					? (
							await unwrap(
								api.DELETE('/api/v1/targets/{target}/dhcp/static-leases', { params, body: { lease: { value: staticLease.value } } })
							)
						).results
					: [];
			reportResults(results, text);
		} catch (e) {
			reportFailure(e, text);
		} finally {
			busy = false;
			open = false;
			await ondeleted();
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>{lease ? 'Delete this lease?' : 'Delete this static lease?'}</AlertDialog.Title>
			<AlertDialog.Description>
				{#if lease}
					{targetName} forgets that <span class="text-foreground font-mono">{lease.ip}</span>
					{lease.name ? `(${lease.name}) ` : ''}is taken. This doesn't block the device: it asks for an address again, and
					may get the same one.
				{:else if staticLease}
					{targetName} stops giving <span class="text-foreground font-mono break-all">{staticLease.mac ?? staticLease.value}</span>
					{staticLease.ip ? `the address ${staticLease.ip}` : 'its fixed address'}. Deleting it restarts DNS and DHCP on the
					Pi-hole, so neither answers for a moment.
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={remove}>
				{busy ? 'Deleting…' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
