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
		needsPassword,
		passwordProblem,
		passwordVariable,
		tlsModeLabel,
		type Instance,
		type TLSMode
	} from '#lib/instances.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// One dialog for adding an instance and for changing one. The password is write-only: it is sent when typed, never
	// shown, and the server keeps it encrypted (or checks it against the instance's env variable, which wins).
	let {
		open = $bindable(false),
		instance = null,
		canStorePasswords,
		onsaved
	}: {
		open: boolean;
		instance?: Instance | null;
		canStorePasswords: boolean;
		onsaved: () => Promise<void> | void;
	} = $props();

	let name = $state('');
	let baseURL = $state('');
	let envName = $state('');
	let tlsMode = $state<TLSMode>('verify');
	let caFile = $state('');
	let password = $state('');
	let passwordAgain = $state('');
	// Set when the server answered that it needs the password, for a reason only it can know (the new env variable is
	// set). From then on the form asks for it.
	let serverWantsPassword = $state(false);
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
		password = '';
		passwordAgain = '';
		serverWantsPassword = false;
		error = null;
		touched = false;
	});

	let editing = $derived(instance !== null);
	let conn = $derived({ base_url: baseURL, env_name: envName, tls_mode: tlsMode, ca_file: caFile });
	// While adding, the password is optional (it can be stored later). While editing, it is only asked for when the
	// password would go to a new address, or when the server said so.
	let askPassword = $derived(!instance || serverWantsPassword || needsPassword(instance, conn));
	let passwordRequired = $derived(instance !== null && (serverWantsPassword || needsPassword(instance, conn)));
	let hints = $derived({
		name: nameProblem(name),
		base_url: baseURLProblem(baseURL),
		env_name: envNameProblem(envName),
		ca_file: caFileProblem(caFile, tlsMode, baseURL),
		password:
			askPassword && (passwordRequired || password !== '' || passwordAgain !== '')
				? passwordProblem(password, passwordAgain)
				: null
	});
	let ready = $derived(Object.values(hints).every((h) => h === null));
	let showCAFile = $derived(tlsMode === 'verify' && isHTTPS(baseURL));
	let willTest = $derived(
		instance?.enabled === true && (connectionChanged(instance, conn) || (askPassword && password !== ''))
	);

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
			...(showCAFile && caFile.trim() !== '' ? { ca_file: caFile.trim() } : {}),
			...(askPassword && password !== '' ? { password } : {})
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
						: canStorePasswords
							? `${saved.name} added. Store its password, then enable it.`
							: `${saved.name} added. Set ${saved.password_variable ?? 'its password variable'} and restart the server, then enable it.`
				);
			}
			open = false;
			await onsaved();
		} catch (e) {
			// Shown in the dialog, which stays open, so the settings can be fixed and saved again.
			if (e instanceof ApiError) {
				if (e.details.field === 'password') serverWantsPassword = true;
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
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{editing ? `Edit ${instance?.name}` : 'Add an instance'}</Dialog.Title>
			<Dialog.Description>
				{#if editing}
					Change how pihole-rbac reaches this Pi-hole.
				{:else}
					A new instance starts disabled. Enable it once it has a password.
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

			{#if askPassword}
				<fieldset class="grid gap-2" disabled={!canStorePasswords && envName.trim() === ''}>
					<legend class="mb-2 text-sm font-medium">
						App password{passwordRequired ? '' : ' (optional)'}
					</legend>
					{#if passwordRequired && !serverWantsPassword}
						<p class="text-muted-foreground text-sm">
							Enter the password again to use the new address: a saved password is only sent to the address it was
							entered for.
						</p>
					{/if}
					<Label for="instance-password" class="sr-only">App password</Label>
					<Input
						id="instance-password"
						type="password"
						bind:value={password}
						autocomplete="new-password"
						placeholder="App password"
						aria-invalid={touched && hints.password !== null}
						aria-describedby="instance-password-hint"
					/>
					<Label for="instance-password-again" class="sr-only">App password again</Label>
					<Input
						id="instance-password-again"
						type="password"
						bind:value={passwordAgain}
						autocomplete="new-password"
						placeholder="App password again"
						aria-invalid={touched && hints.password !== null}
					/>
					{#if touched && hints.password}
						<p id="instance-password-hint" class="text-destructive text-sm">{hints.password}</p>
					{:else if !canStorePasswords}
						<p id="instance-password-hint" class="text-muted-foreground text-sm">
							Passwords can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Until then, give an env
							name below and set its variable; a password entered here only confirms that variable.
						</p>
					{:else}
						<p id="instance-password-hint" class="text-muted-foreground text-sm">
							The Pi-hole's app password, from Settings → Web interface / API. It is stored encrypted and never shown
							again.
						</p>
					{/if}
				</fieldset>
			{/if}

			<div class="grid gap-2">
				<Label for="instance-env">Env name (optional)</Label>
				<Input
					id="instance-env"
					bind:value={envName}
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
						{#if envName.trim() !== ''}
							When <code class="break-all">{passwordVariable(envName.trim())}</code> (or its <code>_FILE</code> form)
							is set, it overrides the stored password. A new variable needs a server restart.
						{:else}
							To manage the password outside the app, name a variable here.
						{/if}
					</p>
				{/if}
			</div>

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
