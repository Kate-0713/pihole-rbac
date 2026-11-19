<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		caFileProblem,
		defaultPort,
		formInput,
		guardWarnings,
		hostProblem,
		nameProblem,
		needsPlainConfirm,
		portProblem,
		transportLabel,
		type DestinationForm,
		type LogDestination,
		type LogTLSMode,
		type LogTransport
	} from '#lib/logdestinations.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// One dialog for adding a destination and for changing one. A new destination receives new events only. Saving a
	// change that sends the log somewhere else, or switches it off, tells the place it was sending to.
	let {
		open = $bindable(false),
		destination = null,
		onsaved
	}: { open: boolean; destination?: LogDestination | null; onsaved: () => Promise<void> | void } = $props();

	let name = $state('');
	let host = $state('');
	let port = $state('');
	let transport = $state<LogTransport>('tls');
	let tlsMode = $state<LogTLSMode>('verify');
	let caFile = $state('');
	let enabled = $state(true);
	// Plain tcp and udp send the log unencrypted, so choosing one has to be agreed to.
	let agreed = $state(false);
	// Until the port is typed, it follows the transport's usual one.
	let portTyped = $state(false);
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	// Svelte 5: $effect re-runs when the state it reads changes. This one fills the form whenever the dialog opens.
	$effect(() => {
		if (!open) return;
		name = destination?.name ?? '';
		host = destination?.host ?? '';
		port = String(destination?.port ?? defaultPort('tls'));
		transport = destination?.transport ?? 'tls';
		tlsMode = destination?.tls_mode ?? 'verify';
		caFile = destination?.ca_file ?? '';
		enabled = destination?.enabled ?? true;
		agreed = false;
		portTyped = destination !== null;
		error = null;
		touched = false;
	});

	function chooseTransport(t: LogTransport) {
		transport = t;
		if (!portTyped) port = String(defaultPort(t));
		agreed = false;
	}

	let form = $derived<DestinationForm>({ host, port, transport, tlsMode, caFile, enabled });
	let confirmNeeded = $derived(needsPlainConfirm(destination, transport));
	let hints = $derived({
		name: nameProblem(name),
		host: hostProblem(host),
		port: portProblem(port),
		ca_file: transport === 'tls' && tlsMode === 'verify' ? caFileProblem(caFile) : null,
		agreed: confirmNeeded && !agreed ? 'Tick the box to send the log unencrypted.' : null
	});
	let ready = $derived(Object.values(hints).every((h) => h === null));
	let warnings = $derived(guardWarnings(destination, form));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const body = formInput(name, form);
		const query = confirmNeeded ? { confirm: true } : {};
		try {
			if (destination) {
				const saved = await unwrap(
					api.PUT('/api/v1/settings/log-destinations/{id}', { params: { path: { id: destination.id }, query }, body })
				);
				notices.success(`${saved.name} saved.`);
			} else {
				const saved = await unwrap(api.POST('/api/v1/settings/log-destinations', { params: { query }, body }));
				notices.success(`${saved.name} added.`);
			}
			open = false;
			await onsaved();
		} catch (e) {
			// Shown in the dialog, which stays open, so the settings can be fixed and saved again.
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-xl">
		<Dialog.Header>
			<Dialog.Title>{destination ? `Edit ${destination.name}` : 'Add a destination'}</Dialog.Title>
			<Dialog.Description>
				{destination
					? 'Where the audit log is sent, as syslog.'
					: 'A syslog collector. It receives the entries from now on, not the ones already in the log.'}
			</Dialog.Description>
		</Dialog.Header>

		<form id="log-destination-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="logdest-name">Name</Label>
				<Input
					id="logdest-name"
					bind:value={name}
					autocomplete="off"
					placeholder="Graylog"
					aria-invalid={touched && hints.name !== null}
					aria-describedby="logdest-name-hint"
				/>
				{#if touched && hints.name}<p id="logdest-name-hint" class="text-destructive text-sm">{hints.name}</p>{/if}
			</div>

			<div class="grid gap-4 sm:grid-cols-[1fr_8rem]">
				<div class="grid gap-2">
					<Label for="logdest-host">Host</Label>
					<Input
						id="logdest-host"
						bind:value={host}
						class="font-mono"
						autocomplete="off"
						spellcheck={false}
						placeholder="logs.example.com"
						aria-invalid={touched && hints.host !== null}
						aria-describedby="logdest-host-hint"
					/>
					{#if touched && hints.host}<p id="logdest-host-hint" class="text-destructive text-sm">{hints.host}</p>{/if}
				</div>
				<div class="grid gap-2">
					<Label for="logdest-port">Port</Label>
					<Input
						id="logdest-port"
						bind:value={port}
						oninput={() => (portTyped = true)}
						class="font-mono"
						inputmode="numeric"
						autocomplete="off"
						aria-invalid={touched && hints.port !== null}
						aria-describedby="logdest-port-hint"
					/>
					{#if touched && hints.port}<p id="logdest-port-hint" class="text-destructive text-sm">{hints.port}</p>{/if}
				</div>
			</div>

			<div class="grid gap-2">
				<Label for="logdest-transport">Transport</Label>
				<Select.Root type="single" value={transport} onValueChange={(v) => chooseTransport(v as LogTransport)}>
					<Select.Trigger id="logdest-transport" class="w-full">{transportLabel[transport]}</Select.Trigger>
					<Select.Content>
						{#each Object.entries(transportLabel) as [value, label] (value)}
							<Select.Item {value} {label}>{label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>

			{#if transport === 'tls'}
				<div class="flex items-start gap-2">
					<Checkbox
						id="logdest-insecure"
						class="mt-0.5"
						checked={tlsMode === 'insecure'}
						onCheckedChange={(c) => (tlsMode = c ? 'insecure' : 'verify')}
						aria-describedby="logdest-insecure-note"
					/>
					<div class="grid gap-0.5">
						<Label for="logdest-insecure" class="font-normal">Don’t check the collector’s certificate</Label>
						<p id="logdest-insecure-note" class="text-muted-foreground text-xs">
							The log is encrypted, but anyone can pose as the collector. For a lab.
						</p>
					</div>
				</div>
				{#if tlsMode === 'verify'}
					<div class="grid gap-2">
						<Label for="logdest-ca">CA file (optional)</Label>
						<Input
							id="logdest-ca"
							bind:value={caFile}
							class="font-mono"
							autocomplete="off"
							spellcheck={false}
							placeholder="/etc/pihole-rbac/collector-ca.pem"
							aria-invalid={touched && hints.ca_file !== null}
							aria-describedby="logdest-ca-hint"
						/>
						{#if touched && hints.ca_file}
							<p id="logdest-ca-hint" class="text-destructive text-sm">{hints.ca_file}</p>
						{:else}
							<p id="logdest-ca-hint" class="text-muted-foreground text-sm">
								A PEM file of certificates to trust as well as the system’s, for a collector with its own CA. It is
								read on the server each time a connection is made.
							</p>
						{/if}
					</div>
				{/if}
			{:else}
				<Alert variant="destructive">
					<AlertDescription>
						{transport === 'tcp' ? 'TCP' : 'UDP'} sends the audit log unencrypted, so anyone on the path can read it
						{transport === 'udp' ? ', and UDP can’t say whether a message arrived' : ''}.
					</AlertDescription>
				</Alert>
				{#if confirmNeeded}
					<div class="grid gap-2">
						<div class="flex items-center gap-2">
							<Checkbox id="logdest-agree" bind:checked={agreed} aria-describedby="logdest-agree-hint" />
							<Label for="logdest-agree" class="font-normal">Send the log unencrypted</Label>
						</div>
						{#if touched && hints.agreed}<p id="logdest-agree-hint" class="text-destructive text-sm">{hints.agreed}</p>{/if}
					</div>
				{/if}
			{/if}

			<div class="flex items-center gap-2">
				<Checkbox id="logdest-enabled" bind:checked={enabled} />
				<Label for="logdest-enabled" class="font-normal">Enabled</Label>
			</div>

			{#if warnings.length > 0}
				<Alert>
					<AlertDescription>
						Saving tells the place it sends to now that {warnings.join(' and ')}, and sends it everything up to this
						change, so a change like this can’t go unnoticed.
					</AlertDescription>
				</Alert>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="log-destination-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if destination}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
