<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { formatMinutes, generalProblems, idleRange, lifetimeRange, type GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// How long sessions last. A new lifetime applies to sessions started after saving; a new idle timeout to every
	// session at once, so shortening it can log idle people out straight away.
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	// bind:value on an <input type="number"> gives a number (or null when the field is empty), not a string: Svelte
	// converts it.
	let lifetime = $state<number | null>(null);
	let idle = $state<number | null>(null);
	$effect(() => {
		lifetime = settings.session_lifetime_minutes;
		idle = settings.idle_timeout_minutes;
	});

	let busy = $state(false);
	let error = $state<string | null>(null);
	let hints = $derived(generalProblems(lifetime ?? Number.NaN, idle ?? Number.NaN));
	let changed = $derived(lifetime !== settings.session_lifetime_minutes || idle !== settings.idle_timeout_minutes);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (hints.lifetime || hints.idle || lifetime === null || idle === null) return;
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/general', { body: { session_lifetime_minutes: lifetime, idle_timeout_minutes: idle } })
			);
			notices.success('Session settings saved.');
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Sessions</h2></Card.Title>
		<Card.Description>How long people stay logged in.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="general-settings-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="grid gap-2">
				<Label for="session-lifetime">Session lifetime (minutes)</Label>
				<Input
					id="session-lifetime"
					type="number"
					min={lifetimeRange.min}
					max={lifetimeRange.max}
					step="1"
					bind:value={lifetime}
					class="w-40"
					aria-invalid={hints.lifetime !== null}
					aria-describedby="session-lifetime-hint"
				/>
				<p id="session-lifetime-hint" class={hints.lifetime ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
					{hints.lifetime ?? `${formatMinutes(lifetime ?? 0)} from login. Applies to sessions started after saving.`}
				</p>
			</div>
			<div class="grid gap-2">
				<Label for="idle-timeout">Idle timeout (minutes)</Label>
				<Input
					id="idle-timeout"
					type="number"
					min={idleRange.min}
					max={idleRange.max}
					step="1"
					bind:value={idle}
					class="w-40"
					aria-invalid={hints.idle !== null}
					aria-describedby="idle-timeout-hint"
				/>
				<p id="idle-timeout-hint" class={hints.idle ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
					{hints.idle ??
						`A session ends after ${formatMinutes(idle ?? 0)} without requests. Applies to every session at once.`}
				</p>
			</div>
		</form>
	</Card.Content>
	<Card.Footer class="flex flex-wrap items-center gap-3">
		<Button type="submit" form="general-settings-form" disabled={busy || !changed || hints.lifetime !== null || hints.idle !== null}>
			{busy ? 'Saving…' : 'Save'}
		</Button>
		<p class="text-muted-foreground text-xs">
			{settings.updated_at
				? `Last saved ${formatDateTime(settings.updated_at)}${settings.updated_by ? ` by ${settings.updated_by}` : ''}.`
				: 'The defaults: 8 hours, and 1 hour idle.'}
		</p>
	</Card.Footer>
</Card.Root>
