<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { describeStatic, hostnameProblem, macProblem, normalMac, staticIPProblem, type DHCPStaticLease } from '#lib/dhcp.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';

	// One dialog for adding a static lease, changing one, and making one from a lease ("prefill"). A change is sent as
	// the entry's own string (from) and the new fields (to); the server adds the new one and then deletes the old, with
	// one restart. An entry the app couldn't have written can't be changed in place: the dialog offers to replace it.
	let {
		open = $bindable(false),
		target,
		targetName,
		entry = null,
		prefill = null,
		subnet = null,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		entry?: DHCPStaticLease | null;
		// Fields to start from when there is no entry: a lease being made static.
		prefill?: { mac: string; ip: string; hostname: string } | null;
		// The subnet DHCP serves, as a prefix, when the settings give one.
		subnet?: string | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let mac = $state('');
	let ip = $state('');
	let hostname = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	// Filled each time the dialog opens. It reads only open, entry and prefill, so typing doesn't reset the fields.
	$effect(() => {
		if (!open) return;
		mac = entry?.mac ?? prefill?.mac ?? '';
		ip = entry?.ip ?? prefill?.ip ?? '';
		hostname = entry?.hostname ?? prefill?.hostname ?? '';
		error = null;
		touched = false;
	});

	let replacing = $derived(entry !== null && entry.marks.length > 0);
	let macHint = $derived(macProblem(mac));
	let ipHint = $derived(staticIPProblem(ip, subnet));
	let nameHint = $derived(hostnameProblem(hostname));
	let ready = $derived(!macHint && !ipHint && !nameHint);
	let title = $derived(!entry ? 'Add a static lease' : replacing ? 'Replace static lease' : 'Change static lease');

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const fields = { mac: mac.trim(), ip: ip.trim(), ...(hostname.trim() !== '' ? { hostname: hostname.trim() } : {}) };
		const shown = describeStatic(normalMac(mac), ip.trim(), hostname.trim().toLowerCase() || undefined);
		const params = { path: { target } };
		const path = '/api/v1/targets/{target}/dhcp/static-leases';
		try {
			const results = entry
				? (await unwrap(api.PATCH(path, { params, body: { from: { value: entry.value }, to: fields } }))).results
				: (await unwrap(api.POST(path, { params, body: fields }))).results;
			reportResults(results, { done: entry ? `${shown} saved` : `${shown} added`, failed: `Couldn't save ${shown}` });
			if (results.some((r) => r.restart_pending)) {
				notices.info(`${targetName} hadn't answered again after restarting DNS and DHCP. Check that it's running.`);
			}
			open = false;
			await onsaved();
		} catch (e) {
			error = failureMessage(e);
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{title}</Dialog.Title>
			<Dialog.Description>
				{#if replacing && entry}
					<span class="font-mono break-all">{entry.value}</span> was added outside the app, with more than the app writes.
					Saving adds the lease below and deletes that one.
				{:else if entry}
					A change adds the new lease on {targetName}, then deletes the old one.
				{:else}
					The device with this hardware address is always given this address{hostname.trim() ? ' and name' : ''}.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="dhcp-static-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="dhcp-static-mac">Hardware address</Label>
				<Input
					id="dhcp-static-mac"
					bind:value={mac}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder="aa:bb:cc:dd:ee:ff"
					aria-invalid={touched && macHint !== null}
					aria-describedby="dhcp-static-mac-hint"
				/>
				{#if touched && macHint}<p id="dhcp-static-mac-hint" class="text-destructive text-sm">{macHint}</p>{/if}
			</div>

			<div class="grid gap-2">
				<Label for="dhcp-static-ip">Address</Label>
				<Input
					id="dhcp-static-ip"
					bind:value={ip}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder="192.168.1.10"
					aria-invalid={touched && ipHint !== null}
					aria-describedby="dhcp-static-ip-hint"
				/>
				<p id="dhcp-static-ip-hint" class={touched && ipHint ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}>
					{#if touched && ipHint}{ipHint}{:else if subnet}IPv4, in {subnet}. It can be outside the range handed out to other devices.{:else}IPv4.{/if}
				</p>
			</div>

			<div class="grid gap-2">
				<Label for="dhcp-static-name">Name (optional)</Label>
				<Input
					id="dhcp-static-name"
					bind:value={hostname}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder="nas"
					aria-invalid={touched && nameHint !== null}
					aria-describedby="dhcp-static-name-hint"
				/>
				<p id="dhcp-static-name-hint" class={touched && nameHint ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}>
					{touched && nameHint ? nameHint : 'One name, with no dots. The device is given it when it asks for an address.'}
				</p>
			</div>

			<p class="text-muted-foreground text-sm">Saving restarts DNS and DHCP on {targetName}, so neither answers for a moment.</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="dhcp-static-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if entry}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
