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
	import { lengthText } from '#lib/schedules.js';
	import type { GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// The longest a schedule's Pi-hole group window can be. Like the other general settings, the save sends the session
	// settings as they were loaded alongside it. Entered in hours and minutes, kept in minutes.
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	const min = 5;
	const max = 365 * 24 * 60;
	// bind:value on a number input gives a number, or null when the field is empty.
	let hours = $state<number | null>(24);
	let minutes = $state<number | null>(0);
	$effect(() => {
		hours = Math.floor(settings.schedule_group_window_max_minutes / 60);
		minutes = settings.schedule_group_window_max_minutes % 60;
	});
	let total = $derived((hours ?? 0) * 60 + (minutes ?? 0));
	let problem = $derived.by(() => {
		if (hours === null && minutes === null) return 'Enter a length.';
		if (!Number.isInteger(hours ?? 0) || !Number.isInteger(minutes ?? 0) || (hours ?? 0) < 0 || (minutes ?? 0) < 0 || (minutes ?? 0) > 59) {
			return 'Hours and minutes are whole numbers, minutes 0 to 59.';
		}
		if (total < min || total > max) return 'A group window can be limited to 5 minutes to 365 days.';
		return null;
	});
	let changed = $derived(total !== settings.schedule_group_window_max_minutes);

	let busy = $state(false);
	let error = $state<string | null>(null);

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
						schedule_group_window_max_minutes: total
					}
				})
			);
			notices.success(`Group windows can now be up to ${lengthText(total)} long.`);
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root role="region" aria-labelledby="schedules-settings-title">
	<Card.Header>
		<Card.Title><h2 id="schedules-settings-title">Schedules</h2></Card.Title>
		<Card.Description>How long a schedule can keep a Pi-hole group switched on or off.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="schedules-settings-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="flex flex-wrap items-end gap-4">
				<div class="grid gap-2">
					<Label for="group-window-hours">Hours</Label>
					<Input id="group-window-hours" type="number" min="0" class="w-28" bind:value={hours} disabled={busy} />
				</div>
				<div class="grid gap-2">
					<Label for="group-window-minutes">Minutes</Label>
					<Input id="group-window-minutes" type="number" min="0" max="59" class="w-24" bind:value={minutes} disabled={busy} />
				</div>
			</div>
			<p class={problem ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'} aria-live="polite">
				{problem ??
					`Longest group window: ${lengthText(total)}. A weekly window is at most 7 days whatever this says, and a blocking window at most 24 hours. Lowering it leaves existing schedules running, marked as over the limit until they're changed.`}
			</p>
		</form>
	</Card.Content>
	<Card.Footer>
		<Button type="submit" form="schedules-settings-form" disabled={busy || !changed || problem !== null}>
			{busy ? 'Saving…' : 'Save'}
		</Button>
	</Card.Footer>
</Card.Root>
