<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { untrack } from 'svelte';
	import { api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import {
		changedSettings,
		formOf,
		prefixText,
		settingsConfirmation,
		settingsProblems,
		subnetOf,
		type DHCPInstance,
		type SettingsConfirmation,
		type SettingsField,
		type SettingsForm
	} from '#lib/dhcp.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';

	// The DHCP settings of one instance, shown even when DHCP is off so it can be turned on. Saving sends only what
	// changed. Pi-hole restarts DNS and DHCP for any change; the server asks to confirm turning DHCP on or off and
	// changing the range, router, netmask or unknown-client rule, and says what changes, which this shows before going on.
	let {
		target,
		instance,
		canEdit,
		onsaved
	}: {
		target: string;
		instance: DHCPInstance;
		// The permission (dhcp.config) and an instance the app can change.
		canEdit: boolean;
		onsaved: () => Promise<void> | void;
	} = $props();

	// $state is a reactive variable: assigning to form.start in a handler updates everything that reads it.
	let form = $state<SettingsForm>(untrack(() => formOf(instance.settings)));
	let touched = $state(false);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let confirm = $state<SettingsConfirmation | null>(null);
	let confirmOpen = $state(false);

	// $effect re-runs when what it reads changes: here, when a save (or someone else's change) gives the instance new
	// settings, so the form shows them. It doesn't read the form, so typing doesn't reset it.
	$effect(() => {
		form = formOf(instance.settings);
		touched = false;
		error = null;
	});

	let problems = $derived(settingsProblems(form));
	let patch = $derived(changedSettings(instance.settings, form));
	let changed = $derived(Object.keys(patch).length > 0);
	let sub = $derived(subnetOf(form.start, form.netmask));
	const locked = (k: string) => instance.locked.includes(k);
	let disabled = $derived(!canEdit || busy);

	async function send(confirmed: boolean) {
		busy = true;
		error = null;
		try {
			const { results } = await unwrap(
				api.PATCH('/api/v1/targets/{target}/dhcp/settings', {
					params: { path: { target }, query: confirmed ? { confirm: true } : {} },
					body: patch
				})
			);
			reportResults(results, { done: 'DHCP settings saved', failed: "Couldn't save the DHCP settings" });
			if (results.some((r) => r.restart_pending)) {
				notices.info(`${instance.instance} hadn't answered again after restarting DNS and DHCP. Check that it's running.`);
			}
			confirmOpen = false;
			confirm = null;
			await onsaved();
		} catch (e) {
			const c = settingsConfirmation(e);
			if (c && !confirmed) {
				confirm = c;
				confirmOpen = true;
			} else {
				confirmOpen = false;
				error = failureMessage(e);
			}
		} finally {
			busy = false;
		}
	}

	function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!changed || Object.keys(problems).length > 0) return;
		return send(false);
	}

	const hint = (k: SettingsField) => (touched ? problems[k] : undefined);
</script>

<form class="grid max-w-2xl gap-4" onsubmit={save} oninput={() => (touched = true)} aria-label="DHCP settings">
	{#if error}
		<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
	{/if}

	<div class="flex items-center gap-2">
		<Checkbox id="dhcp-active" bind:checked={form.active} disabled={disabled || locked('active')} />
		<Label for="dhcp-active">DHCP server on</Label>
	</div>

	<div class="grid gap-4 sm:grid-cols-2">
		{#each [{ k: 'start', label: 'Start of range', ph: '192.168.1.100' }, { k: 'end', label: 'End of range', ph: '192.168.1.200' }, { k: 'router', label: 'Router', ph: '192.168.1.1' }, { k: 'netmask', label: 'Netmask (optional)', ph: '255.255.255.0' }] as const as f (f.k)}
			<div class="grid gap-2">
				<Label for="dhcp-{f.k}">{f.label}</Label>
				<Input
					id="dhcp-{f.k}"
					bind:value={form[f.k]}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder={f.ph}
					disabled={disabled || locked(f.k)}
					aria-invalid={f.k !== 'netmask' || hint('netmask') ? hint(f.k) !== undefined : false}
					aria-describedby="dhcp-{f.k}-hint"
				/>
				{#if hint(f.k)}<p id="dhcp-{f.k}-hint" class="text-destructive text-sm">{hint(f.k)}</p>{/if}
				{#if locked(f.k)}<p class="text-muted-foreground text-xs">Set by an environment variable on the Pi-hole.</p>{/if}
			</div>
		{/each}
	</div>
	<p class="text-muted-foreground text-xs">
		{#if sub && sub.guessed}
			With no netmask, Pi-hole works out the subnet from the class of the start address: {prefixText(sub)}.
		{:else if sub}
			Subnet {prefixText(sub)}.
		{:else}
			The router can't be inside the range. Addresses are IPv4.
		{/if}
	</p>

	<div class="grid max-w-xs gap-2">
		<Label for="dhcp-lease_time">Lease time</Label>
		<Input
			id="dhcp-lease_time"
			bind:value={form.lease_time}
			class="w-32"
			autocomplete="off"
			placeholder="24h"
			disabled={disabled || locked('lease_time')}
			aria-invalid={hint('lease_time') !== undefined}
			aria-describedby="dhcp-lease_time-hint"
		/>
		<p id="dhcp-lease_time-hint" class={hint('lease_time') ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}>
			{hint('lease_time') ?? "Seconds, or a number with m, h, d or w (45m, 12h, 7d), from 2 minutes to 365 days. Empty uses dnsmasq's default."}
		</p>
	</div>

	<fieldset class="grid gap-3">
		<legend class="mb-1 text-sm font-medium">Options</legend>
		{#each [{ k: 'ignore_unknown_clients', label: 'Only serve devices with a static lease', note: 'Every other device is ignored, and gets no address.' }, { k: 'ipv6', label: 'IPv6 (router advertisements and DHCPv6)', note: '' }, { k: 'rapid_commit', label: 'Rapid commit', note: 'Faster address assignment for devices that support it.' }, { k: 'multi_dns', label: 'Advertise several DNS servers', note: 'Lets devices be told about other DNS servers as well as Pi-hole.' }] as const as o (o.k)}
			<div class="flex items-start gap-2">
				<Checkbox id="dhcp-{o.k}" class="mt-0.5" bind:checked={form[o.k]} disabled={disabled || locked(o.k)} aria-describedby="dhcp-{o.k}-note" />
				<div class="grid gap-0.5">
					<Label for="dhcp-{o.k}">{o.label}</Label>
					{#if o.note}<p id="dhcp-{o.k}-note" class="text-muted-foreground text-xs">{o.note}</p>{/if}
				</div>
			</div>
		{/each}
	</fieldset>

	{#if canEdit}
		<p class="text-muted-foreground text-sm">Saving restarts DNS and DHCP on {instance.instance}, so neither answers for a moment.</p>
		<div class="flex gap-2">
			<Button type="submit" disabled={busy || !changed || (touched && Object.keys(problems).length > 0)}>
				{busy ? 'Saving…' : 'Save'}
			</Button>
			<Button type="button" variant="outline" disabled={busy || !changed} onclick={() => ((form = formOf(instance.settings)), (touched = false))}>
				Revert
			</Button>
		</div>
	{/if}
</form>

<AlertDialog.Root bind:open={confirmOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Restart DNS and DHCP on {instance.instance}?</AlertDialog.Title>
			<AlertDialog.Description>This change restarts DNS and DHCP on the Pi-hole, and neither answers while it does.</AlertDialog.Description>
		</AlertDialog.Header>
		{#if confirm}
			<ul class="list-disc pl-5 text-sm" aria-label="Changes">
				{#each confirm.summary as line (line)}<li>{line}</li>{/each}
			</ul>
			{#if confirm.otherActive.length > 0}
				<Alert>
					<AlertDescription>
						DHCP is already on for {confirm.otherActive.join(', ')}. Two DHCP servers on one network hand out clashing
						addresses. Go on only if they serve different networks.
					</AlertDescription>
				</Alert>
			{/if}
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action
				disabled={busy}
				onclick={(e: MouseEvent) => {
					e.preventDefault();
					return send(true);
				}}>{busy ? 'Saving…' : 'Save and restart'}</AlertDialog.Action
			>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
