<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		baseURLProblem,
		caFileProblem,
		connectionChanged,
		envNameProblem,
		isHTTPS,
		nameProblem,
		passwordVariable,
		suggestEnvName,
		tlsModeLabel,
		type Instance,
		type TLSMode
	} from '#lib/instances.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// One dialog for adding an instance and for changing one. Passwords never go through it: the server reads each
	// instance's password from its own environment variable.
	let {
		open = $bindable(false),
		instance = null,
		onsaved
	}: {
		open: boolean;
		instance?: Instance | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let name = $state('');
	let baseURL = $state('');
	let envName = $state('');
	let tlsMode = $state<TLSMode>('verify');
	let caFile = $state('');
	// While adding, the env name follows the name until the admin edits it.
	let envEdited = $state(false);
	let error = $state<{ message: string; detail?: string } | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	$effect(() => {
		if (!open) return;
		name = instance?.name ?? '';
		baseURL = instance?.base_url ?? '';
		envName = instance?.env_name ?? '';
		tlsMode = instance?.tls_mode ?? 'verify';
		caFile = instance?.ca_file ?? '';
		envEdited = instance !== null;
		error = null;
		touched = false;
	});

	function onNameInput() {
		if (!envEdited) envName = suggestEnvName(name);
	}

	let editing = $derived(instance !== null);
	let input = $derived({ name, base_url: baseURL, env_name: envName, tls_mode: tlsMode, ca_file: caFile });
	let hints = $derived({
		name: nameProblem(name),
		base_url: baseURLProblem(baseURL),
		env_name: envNameProblem(envName),
		ca_file: caFileProblem(caFile, tlsMode, baseURL)
	});
	let ready = $derived(Object.values(hints).every((h) => h === null));
	// The CA file only means something for a verified https connection; keep what was typed, but hide the field.
	let showCAFile = $derived(tlsMode === 'verify' && isHTTPS(baseURL));
	let willTest = $derived(instance?.enabled === true && connectionChanged(instance, input));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const body = {
			name: name.trim(),
			base_url: baseURL.trim(),
			env_name: envName.trim(),
			tls_mode: tlsMode,
			...(showCAFile && caFile.trim() !== '' ? { ca_file: caFile.trim() } : {})
		};
		try {
			if (instance) {
				const saved = await unwrap(
					api.PUT('/api/v1/instances/{id}', { params: { path: { id: instance.id } }, body })
				);
				notices.success(`${saved.name} saved.`);
			} else {
				const saved = await unwrap(api.POST('/api/v1/instances', { body }));
				notices.success(
					saved.password_set
						? `${saved.name} added. Enable it when you're ready.`
						: `${saved.name} added. Set ${saved.password_variable} and restart the server, then enable it.`
				);
			}
			open = false;
			await onsaved();
		} catch (e) {
			// Shown in the dialog, which stays open, so the settings can be fixed and saved again.
			if (e instanceof ApiError) {
				const detail = typeof e.details.detail === 'string' ? e.details.detail : undefined;
				error = { message: e.message, detail };
			} else {
				error = { message: 'Something went wrong. Try again.' };
			}
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{editing ? `Edit ${instance?.name}` : 'Add an instance'}</Dialog.Title>
			<Dialog.Description>
				{#if editing}
					Change how pihole-rbac reaches this Pi-hole.
				{:else}
					A new instance starts disabled. Enable it once its password variable is set.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="instance-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>
						<p>{error.message}</p>
						{#if error.detail}<p class="font-mono text-xs break-all">{error.detail}</p>{/if}
					</AlertDescription>
				</Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="instance-name">Name</Label>
				<Input
					id="instance-name"
					bind:value={name}
					oninput={onNameInput}
					autocomplete="off"
					placeholder="pihole1"
					aria-invalid={touched && hints.name !== null}
					aria-describedby="instance-name-hint"
				/>
				{#if touched && hints.name}
					<p id="instance-name-hint" class="text-destructive text-sm">{hints.name}</p>
				{/if}
			</div>

			<div class="grid gap-2">
				<Label for="instance-url">Base URL</Label>
				<Input
					id="instance-url"
					bind:value={baseURL}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					inputmode="url"
					placeholder="https://pihole1.lan"
					aria-invalid={touched && hints.base_url !== null}
					aria-describedby="instance-url-hint"
				/>
				{#if touched && hints.base_url}
					<p id="instance-url-hint" class="text-destructive text-sm">{hints.base_url}</p>
				{:else}
					<p id="instance-url-hint" class="text-muted-foreground text-sm">
						The Pi-hole's address, without /admin or /api.
					</p>
				{/if}
			</div>

			<div class="grid gap-2">
				<Label for="instance-env">Env name</Label>
				<Input
					id="instance-env"
					bind:value={envName}
					oninput={() => (envEdited = true)}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder="PIHOLE1"
					aria-invalid={touched && hints.env_name !== null}
					aria-describedby="instance-env-hint"
				/>
				{#if touched && hints.env_name}
					<p id="instance-env-hint" class="text-destructive text-sm">{hints.env_name}</p>
				{:else}
					<p id="instance-env-hint" class="text-muted-foreground text-sm">
						The app password is read from <code class="break-all">{passwordVariable(envName.trim())}</code> (or its
						<code>_FILE</code> form). A new variable needs a server restart.
					</p>
				{/if}
			</div>

			<div class="grid gap-2">
				<Label for="instance-tls">Certificate</Label>
				<Select.Root type="single" bind:value={tlsMode}>
					<Select.Trigger id="instance-tls" class="w-full">{tlsModeLabel[tlsMode]}</Select.Trigger>
					<Select.Content>
						<Select.Item value="verify" label={tlsModeLabel.verify}>{tlsModeLabel.verify}</Select.Item>
						<Select.Item value="insecure" label={tlsModeLabel.insecure}>{tlsModeLabel.insecure}</Select.Item>
					</Select.Content>
				</Select.Root>
			</div>

			{#if showCAFile}
				<div class="grid gap-2">
					<Label for="instance-ca">CA file (optional)</Label>
					<Input
						id="instance-ca"
						bind:value={caFile}
						class="font-mono"
						autocomplete="off"
						spellcheck={false}
						placeholder="/etc/pihole-rbac/pihole-ca.pem"
						aria-invalid={touched && hints.ca_file !== null}
						aria-describedby="instance-ca-hint"
					/>
					{#if touched && hints.ca_file}
						<p id="instance-ca-hint" class="text-destructive text-sm">{hints.ca_file}</p>
					{:else}
						<p id="instance-ca-hint" class="text-muted-foreground text-sm">
							A PEM file on the server to trust as well as the system's CAs, such as the Pi-hole's own CA.
						</p>
					{/if}
				</div>
			{/if}

			{#if willTest}
				<p class="text-muted-foreground text-sm">
					This instance is enabled, so the new connection settings are tested before they're saved. To save
					settings that don't work yet, disable it first.
				</p>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="instance-form" disabled={busy || (touched && !ready)}>
				{#if busy}{willTest ? 'Testing…' : 'Saving…'}{:else if editing}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
