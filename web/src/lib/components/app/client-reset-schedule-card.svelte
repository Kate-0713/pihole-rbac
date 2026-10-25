<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { browserZone, nextRun, scheduleProblem, timeZones, type Schedule } from '#lib/clientreset.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { formatDateTime } from '#lib/format.js';
	import type { GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// When client reset runs by itself. The schedule is one of the general settings, which are saved together, so the
	// save sends the session settings as they were loaded alongside it (and leaves the audit retention out, which keeps
	// it as it is).
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	let enabled = $state(false);
	let time = $state('');
	let zone = $state('');
	// The form starts again from the saved schedule whenever it changes (after a save, say). A schedule that has never
	// been switched on suggests the browser's own time zone rather than UTC.
	$effect(() => {
		const s = settings.client_reset_schedule;
		enabled = s.enabled;
		time = s.time;
		zone = !s.enabled && !settings.updated_at ? browserZone() : s.time_zone;
	});

	let busy = $state(false);
	let error = $state<string | null>(null);
	const zones = timeZones();
	let draft = $derived<Schedule>({ enabled, time, time_zone: zone.trim() });
	let problem = $derived(scheduleProblem(draft));
	let saved = $derived(settings.client_reset_schedule);
	let changed = $derived(draft.enabled !== saved.enabled || draft.time !== saved.time || draft.time_zone !== saved.time_zone);
	let next = $derived(problem === null ? nextRun(draft, new Date()) : null);
	let browser = browserZone();

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (problem) return;
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/general', {
					body: {
						session_lifetime_minutes: settings.session_lifetime_minutes,
						idle_timeout_minutes: settings.idle_timeout_minutes,
						client_reset_schedule: draft
					}
				})
			);
			notices.success(draft.enabled ? `Client reset will run daily at ${draft.time} (${draft.time_zone}).` : 'Scheduled client reset is off.');
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
		<Card.Title><h2>Schedule</h2></Card.Title>
		<Card.Description>Run every instance's and group's rules once a day. Runs on demand work either way.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="client-reset-schedule-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="flex items-center gap-2">
				<Checkbox id="reset-schedule-enabled" bind:checked={enabled} />
				<Label for="reset-schedule-enabled">Run daily</Label>
			</div>
			<div class="grid gap-4 sm:grid-cols-[10rem_1fr]">
				<div class="grid gap-2">
					<Label for="reset-schedule-time">Run at</Label>
					<Input id="reset-schedule-time" type="time" bind:value={time} required />
				</div>
				<div class="grid gap-2">
					<Label for="reset-schedule-zone">Time zone</Label>
					<!-- A text field with suggestions: the browser's list of zones, offered as you type. -->
					<Input id="reset-schedule-zone" list="reset-schedule-zones" bind:value={zone} autocomplete="off" spellcheck={false} />
					<datalist id="reset-schedule-zones">
						{#each zones as z (z)}<option value={z}></option>{/each}
					</datalist>
				</div>
			</div>
			<p class={problem ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'} aria-live="polite">
				{#if problem}
					{problem}
				{:else if !enabled}
					Off: client reset only runs when someone runs it.
				{:else if next}
					Next run {formatDateTime(next.toISOString(), undefined, draft.time_zone)} ({draft.time_zone}){draft.time_zone !== browser
						? `, which is ${formatDateTime(next.toISOString())} here`
						: ''}.
				{/if}
			</p>
			<p class="text-muted-foreground text-xs">
				A time skipped when the clocks go forward runs an hour later that night. A run the app misses, because it was
				stopped or the host was asleep, isn't made up later.
			</p>
		</form>
	</Card.Content>
	<Card.Footer>
		<Button type="submit" form="client-reset-schedule-form" disabled={busy || !changed || problem !== null}>
			{busy ? 'Saving…' : 'Save'}
		</Button>
	</Card.Footer>
</Card.Root>
