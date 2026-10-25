<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import EventChecklist from '#lib/components/app/event-checklist.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		envNameProblem,
		guardWarnings,
		homeserverProblem,
		kindLabel,
		nameProblem,
		needsSecret,
		roomProblem,
		secretProblem,
		secretVariable,
		secretWord,
		type Channel,
		type ChannelInput,
		type ChannelKind,
		type NotificationEvent
	} from '#lib/notifications.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// One dialog for adding a channel and for changing one. The secret (a Discord webhook URL or a Matrix access token)
	// is write-only: sent when given, never shown. A channel's kind is chosen when it is added and can't change.
	let {
		open = $bindable(false),
		channel = null,
		events,
		canStoreSecrets,
		onsaved
	}: {
		open: boolean;
		channel?: Channel | null;
		events: NotificationEvent[];
		canStoreSecrets: boolean;
		onsaved: () => Promise<void> | void;
	} = $props();

	let kind = $state<ChannelKind>('discord');
	let name = $state('');
	let envName = $state('');
	let enabled = $state(true);
	let selected = $state<string[]>([]);
	let homeserver = $state('');
	let room = $state('');
	let allowHTTP = $state(false);
	let secret = $state('');
	// Set when the server answered that it needs the secret, for a reason only it can know (the channel's variable is
	// set). From then on the form asks for it.
	let serverWantsSecret = $state(false);
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	$effect(() => {
		if (!open) return;
		kind = channel?.kind ?? 'discord';
		name = channel?.name ?? '';
		envName = channel?.env_name ?? '';
		enabled = channel?.enabled ?? true;
		selected = [...(channel?.events ?? [])];
		homeserver = channel?.matrix?.homeserver ?? '';
		room = channel?.matrix?.room_id ?? '';
		allowHTTP = channel?.matrix?.allow_http ?? false;
		secret = '';
		serverWantsSecret = false;
		error = null;
		touched = false;
	});

	let form = $derived({ homeserver, allowHTTP, enabled, events: selected, secret });
	let secretRequired = $derived(serverWantsSecret || needsSecret(channel, form));
	let hints = $derived({
		name: nameProblem(name),
		env_name: envNameProblem(envName),
		homeserver: kind === 'matrix' ? homeserverProblem(homeserver, allowHTTP) : null,
		room: kind === 'matrix' ? roomProblem(room) : null,
		secret: secret !== '' || secretRequired ? secretProblem(kind, secret) : null
	});
	let ready = $derived(Object.values(hints).every((h) => h === null));
	let warnings = $derived(guardWarnings(channel, form));
	// Without a master key a secret can only confirm the channel's variable, so the field needs an env name.
	let secretDisabled = $derived(!canStoreSecrets && envName.trim() === '');

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const body: ChannelInput = {
			kind,
			name: name.trim(),
			env_name: envName.trim(),
			enabled,
			events: selected,
			...(kind === 'matrix' ? { matrix: { homeserver: homeserver.trim(), room_id: room.trim(), allow_http: allowHTTP } } : {}),
			...(secret !== '' ? { secret: secret.trim() } : {})
		};
		try {
			if (channel) {
				const saved = await unwrap(api.PUT('/api/v1/notifications/channels/{id}', { params: { path: { id: channel.id } }, body }));
				notices.success(`${saved.name} saved.`);
			} else {
				const saved = await unwrap(api.POST('/api/v1/notifications/channels', { body }));
				notices.success(
					saved.secret_problem ? `${saved.name} added. It can send once it has a ${secretWord(saved.kind)}.` : `${saved.name} added.`
				);
			}
			open = false;
			await onsaved();
		} catch (e) {
			// Shown in the dialog, which stays open, so the settings can be fixed and saved again.
			if (e instanceof ApiError) {
				if (e.details.field === 'secret') serverWantsSecret = true;
				error = e.message;
			} else {
				error = 'Something went wrong. Try again.';
			}
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
		<Dialog.Header>
			<Dialog.Title>{channel ? `Edit ${channel.name}` : 'Add a channel'}</Dialog.Title>
			<Dialog.Description>
				{channel
					? `A ${kindLabel[channel.kind]} channel. Its kind can't change.`
					: 'Where notifications go, and which events it receives.'}
			</Dialog.Description>
		</Dialog.Header>

		<form id="channel-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}

			{#if !channel}
				<div class="grid gap-2">
					<Label for="channel-kind">Kind</Label>
					<Select.Root type="single" bind:value={kind}>
						<Select.Trigger id="channel-kind" class="w-full">{kindLabel[kind]}</Select.Trigger>
						<Select.Content>
							<Select.Item value="discord" label="Discord">Discord</Select.Item>
							<Select.Item value="matrix" label="Matrix">Matrix</Select.Item>
						</Select.Content>
					</Select.Root>
				</div>
			{/if}

			<div class="grid gap-2">
				<Label for="channel-name">Name</Label>
				<Input
					id="channel-name"
					bind:value={name}
					autocomplete="off"
					placeholder="Ops alerts"
					aria-invalid={touched && hints.name !== null}
					aria-describedby="channel-name-hint"
				/>
				{#if touched && hints.name}<p id="channel-name-hint" class="text-destructive text-sm">{hints.name}</p>{/if}
			</div>

			{#if kind === 'matrix'}
				<div class="grid gap-2">
					<Label for="channel-homeserver">Homeserver</Label>
					<Input
						id="channel-homeserver"
						bind:value={homeserver}
						class="font-mono"
						autocomplete="off"
						spellcheck={false}
						inputmode="url"
						placeholder="https://matrix.example.org"
						aria-invalid={touched && hints.homeserver !== null}
						aria-describedby="channel-homeserver-hint"
					/>
					{#if touched && hints.homeserver}
						<p id="channel-homeserver-hint" class="text-destructive text-sm">{hints.homeserver}</p>
					{:else}
						<p id="channel-homeserver-hint" class="text-muted-foreground text-sm">It can be on your local network.</p>
					{/if}
				</div>
				<div class="flex items-start gap-2">
					<Checkbox id="channel-allow-http" class="mt-0.5" bind:checked={allowHTTP} aria-describedby="channel-allow-http-note" />
					<div class="grid gap-0.5">
						<Label for="channel-allow-http" class="font-normal">Allow plain HTTP</Label>
						<p id="channel-allow-http-note" class="text-muted-foreground text-xs">
							The access token then crosses the network unencrypted. Only for a homeserver on a network you trust.
						</p>
					</div>
				</div>
				<div class="grid gap-2">
					<Label for="channel-room">Room ID</Label>
					<Input
						id="channel-room"
						bind:value={room}
						class="font-mono"
						autocomplete="off"
						spellcheck={false}
						placeholder="!abcdefg:example.org"
						aria-invalid={touched && hints.room !== null}
						aria-describedby="channel-room-hint"
					/>
					{#if touched && hints.room}
						<p id="channel-room-hint" class="text-destructive text-sm">{hints.room}</p>
					{:else}
						<p id="channel-room-hint" class="text-muted-foreground text-sm">
							The account that posts must already be in the room.
						</p>
					{/if}
				</div>
			{/if}

			<fieldset class="grid gap-2" disabled={secretDisabled}>
				<legend class="mb-2 text-sm font-medium">
					{kind === 'discord' ? 'Webhook URL' : 'Access token'}{secretRequired
						? ''
						: channel && channel.secret_source !== 'none'
							? ' (leave empty to keep it)'
							: ' (optional)'}
				</legend>
				{#if secretRequired && !serverWantsSecret}
					<p class="text-muted-foreground text-sm">
						Enter the access token again to use the new homeserver settings: a saved token is only sent where it was
						entered for.
					</p>
				{/if}
				<Label for="channel-secret" class="sr-only">{kind === 'discord' ? 'Webhook URL' : 'Access token'}</Label>
				<Input
					id="channel-secret"
					type="password"
					bind:value={secret}
					autocomplete="off"
					spellcheck={false}
					placeholder={kind === 'discord' ? 'https://discord.com/api/webhooks/…' : 'syt_…'}
					aria-invalid={touched && hints.secret !== null}
					aria-describedby="channel-secret-hint"
				/>
				{#if touched && hints.secret}
					<p id="channel-secret-hint" class="text-destructive text-sm">{hints.secret}</p>
				{:else if secretDisabled}
					<p id="channel-secret-hint" class="text-muted-foreground text-sm">
						Secrets can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Give an env name below and
						set its variable instead.
					</p>
				{:else}
					<p id="channel-secret-hint" class="text-muted-foreground text-sm">
						{kind === 'discord'
							? 'From the Discord channel’s Integrations → Webhooks. It is stored encrypted and never shown again.'
							: 'The token of the account that posts: use a bot account, not your own. It is stored encrypted and never shown again.'}
					</p>
				{/if}
			</fieldset>

			<div class="grid gap-2">
				<Label for="channel-env">Env name (optional)</Label>
				<Input
					id="channel-env"
					bind:value={envName}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder="OPS"
					aria-invalid={touched && hints.env_name !== null}
					aria-describedby="channel-env-hint"
				/>
				{#if touched && hints.env_name}
					<p id="channel-env-hint" class="text-destructive text-sm">{hints.env_name}</p>
				{:else}
					<p id="channel-env-hint" class="text-muted-foreground text-sm">
						{#if envName.trim() !== ''}
							When <code class="break-all">{secretVariable(envName.trim())}</code> (or its <code>_FILE</code> form) is set,
							it overrides the stored {secretWord(kind)}. A new variable needs a server restart.
						{:else}
							To manage the {secretWord(kind)} outside the app, name a variable here.
						{/if}
					</p>
				{/if}
			</div>

			<div class="flex items-center gap-2">
				<Checkbox id="channel-enabled" bind:checked={enabled} />
				<Label for="channel-enabled" class="font-normal">Enabled</Label>
			</div>

			<EventChecklist bind:selected {events} />

			{#if warnings.length > 0}
				<Alert>
					<AlertDescription>
						Saving tells the channel's current destination that {warnings.join('; ')}, so a change like this can't go
						unnoticed.
					</AlertDescription>
				</Alert>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="channel-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if channel}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
