<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { lengthText } from '#lib/schedules.js';
	import type { GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// How long a temporary client change can last, and whether it needs a reason. Like the other general settings, the
	// save sends the session settings as they were loaded alongside it, and what it doesn't send stays as it was.
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	const min = 5;
	const max = 365 * 24 * 60;
	// bind:value on a number input gives a number, or null when the field is empty.
	let hours = $state<number | null>(0);
	let minutes = $state<number | null>(0);
	let reasonRequired = $state(true);
	// Filled from the saved settings, and again after each save (the page reads them again and passes new ones).
	$effect(() => {
		hours = Math.floor(settings.client_temp_max_minutes / 60);
		minutes = settings.client_temp_max_minutes % 60;
		reasonRequired = settings.client_temp_reason_required;
	});
	let total = $derived((hours ?? 0) * 60 + (minutes ?? 0));
	let problem = $derived.by(() => {
		if (hours === null && minutes === null) return 'Enter a length.';
		if (!Number.isInteger(hours ?? 0) || !Number.isInteger(minutes ?? 0) || (hours ?? 0) < 0 || (minutes ?? 0) < 0 || (minutes ?? 0) > 59) {
			return 'Hours and minutes are whole numbers, minutes 0 to 59.';
		}
		if (total < min || total > max) return 'A temporary change can be limited to 5 minutes to 365 days.';
		return null;
	});
	let changed = $derived(total !== settings.client_temp_max_minutes || reasonRequired !== settings.client_temp_reason_required);

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
						client_temp_max_minutes: total,
						client_temp_reason_required: reasonRequired
					}
				})
			);
			notices.success(`Temporary client changes can now last up to ${lengthText(total)}.`);
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root role="region" aria-labelledby="client-temp-settings-title">
	<Card.Header>
		<Card.Title><h2 id="client-temp-settings-title">Temporary client changes</h2></Card.Title>
		<Card.Description>Moving a client to other Pi-hole groups for a while, from the Clients page.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="client-temp-settings-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="flex flex-wrap items-end gap-4">
				<div class="grid gap-2">
					<Label for="client-temp-hours">Hours</Label>
					<Input id="client-temp-hours" type="number" min="0" class="w-28" bind:value={hours} disabled={busy} />
				</div>
				<div class="grid gap-2">
					<Label for="client-temp-minutes">Minutes</Label>
					<Input id="client-temp-minutes" type="number" min="0" max="59" class="w-24" bind:value={minutes} disabled={busy} />
				</div>
			</div>
			<p class={problem ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'} aria-live="polite">
				{problem ??
					`Longest change: ${lengthText(total)}, counted from when it starts, so extending it can't go past that. Lowering it leaves changes already running as they are.`}
			</p>
			<div class="flex items-center gap-2">
				<Checkbox id="client-temp-reason" bind:checked={reasonRequired} disabled={busy} />
				<Label for="client-temp-reason" class="font-normal">Ask for a reason when a change is started</Label>
			</div>
		</form>
	</Card.Content>
	<Card.Footer>
		<Button type="submit" form="client-temp-settings-form" disabled={busy || !changed || problem !== null}>
			{busy ? 'Saving…' : 'Save'}
		</Button>
	</Card.Footer>
</Card.Root>
