<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { formatDuration } from '#lib/format.js';
	import { maxBlockingTimer, durationProblem } from '#lib/blocking.js';

	// Asks how long to turn blocking off for, in hours and minutes, up to the API's 24-hour limit. It only collects
	// the length: onconfirm gets the seconds and the parent sends the change, as it does for the fixed choices.
	let {
		open = $bindable(false),
		onconfirm
	}: {
		open: boolean;
		onconfirm: (seconds: number) => void;
	} = $props();

	// Number inputs bind to number | null (null while the box is empty), so both are kept as that.
	let hours = $state<number | null>(0);
	let minutes = $state<number | null>(15);
	let touched = $state(false);

	// Start from the same values each time the dialog opens.
	$effect(() => {
		if (!open) return;
		hours = 0;
		minutes = 15;
		touched = false;
	});

	let problem = $derived(durationProblem(hours, minutes));
	let seconds = $derived(problem === null ? (hours ?? 0) * 3600 + (minutes ?? 0) * 60 : null);

	function submit(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (seconds === null) return;
		open = false;
		onconfirm(seconds);
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-sm">
		<Dialog.Header>
			<Dialog.Title>Turn blocking off for…</Dialog.Title>
			<Dialog.Description>
				Pi-hole turns blocking back on by itself when the time runs out. Up to {formatDuration(maxBlockingTimer)}.
			</Dialog.Description>
		</Dialog.Header>

		<form id="blocking-duration-form" class="grid gap-2" onsubmit={submit} oninput={() => (touched = true)}>
			<div class="grid grid-cols-2 gap-3">
				<div class="grid gap-1.5">
					<Label for="blocking-hours">Hours</Label>
					<Input
						id="blocking-hours"
						type="number"
						min="0"
						max="24"
						step="1"
						inputmode="numeric"
						bind:value={hours}
						aria-invalid={touched && problem !== null}
						aria-describedby="blocking-duration-hint"
					/>
				</div>
				<div class="grid gap-1.5">
					<Label for="blocking-minutes">Minutes</Label>
					<Input
						id="blocking-minutes"
						type="number"
						min="0"
						max="59"
						step="1"
						inputmode="numeric"
						bind:value={minutes}
						aria-invalid={touched && problem !== null}
						aria-describedby="blocking-duration-hint"
					/>
				</div>
			</div>
			<p
				id="blocking-duration-hint"
				class="text-sm"
				class:text-destructive={touched && problem}
				class:text-muted-foreground={!(touched && problem)}
				aria-live="polite"
			>
				{#if touched && problem}
					{problem}
				{:else if seconds !== null}
					Blocking comes back on after {formatDuration(seconds)}.
				{:else}
					Between 1 minute and {formatDuration(maxBlockingTimer)}.
				{/if}
			</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
			<Button type="submit" form="blocking-duration-form" disabled={touched && problem !== null}>
				Turn blocking off
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
