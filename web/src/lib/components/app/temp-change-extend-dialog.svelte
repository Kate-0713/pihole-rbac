<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { untrack } from 'svelte';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { browserZone } from '#lib/clientreset.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { dateToZoned, zonedToDate } from '#lib/schedules.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { additions, extendProblem, latestEnd, type Limits, type TempChange } from '#lib/temp-changes.js';

	// Changes when a temporary change ends: later (Extend) or sooner. It only changes the app's own record, so no
	// Pi-hole is asked. The limit counts from the change's start, so the latest end is shown.
	let {
		open = $bindable(false),
		target,
		change,
		limits,
		onsaved
	}: {
		open: boolean;
		target: string;
		change: TempChange | null;
		limits: Limits;
		onsaved: () => Promise<void> | void;
	} = $props();

	const zone = browserZone();
	let date = $state('');
	let time = $state('');
	let now = $state(new Date());
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Filled when the dialog opens; the page reloads the change every 30 seconds and that must not reset the fields.
	$effect(() => {
		if (!open || !change) return;
		const endsAt = change.ends_at;
		untrack(() => {
			({ date, time } = dateToZoned(endsAt, zone));
			now = new Date();
			error = null;
		});
	});

	let end = $derived(zonedToDate(date, time, zone));
	let problem = $derived(change ? extendProblem(change, end, limits, now) : null);
	let latest = $derived(change ? latestEnd(change, limits.max_minutes) : null);

	// A quick addition counts from the end it has now, and is offered only while it stays within the limit.
	const fits = (minutes: number) =>
		change !== null && latest !== null && new Date(change.ends_at).getTime() + minutes * 60_000 <= latest.getTime();
	function add(minutes: number) {
		if (!change) return;
		({ date, time } = dateToZoned(new Date(new Date(change.ends_at).getTime() + minutes * 60_000).toISOString(), zone));
	}

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!change || !end) return;
		now = new Date();
		if (extendProblem(change, end, limits, now)) return;
		busy = true;
		error = null;
		try {
			const updated = await unwrap(
				api.PATCH('/api/v1/targets/{target}/clients/temporary/{id}', {
					params: { path: { target, id: change.id } },
					body: { ends_at: end.toISOString() }
				})
			);
			notices.success(`${updated.client} is changed until ${formatDateTime(updated.ends_at)}.`);
			open = false;
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="top-[5vh] max-h-[90vh] translate-y-0 overflow-y-auto sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Change when it ends</Dialog.Title>
			<Dialog.Description>
				{#if change}
					<span class="font-mono break-all">{change.client}</span> goes back to its groups at
					{formatDateTime(change.ends_at)}.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="temp-extend-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="flex flex-wrap gap-2" role="group" aria-label="Add time">
				{#each additions as a (a.minutes)}
					<Button type="button" size="sm" variant="outline" disabled={busy || !fits(a.minutes)} onclick={() => add(a.minutes)}>
						Add {a.label}
					</Button>
				{/each}
			</div>
			<div class="flex flex-wrap items-center gap-2">
				<Input type="date" class="w-40" bind:value={date} aria-label="End date" disabled={busy} />
				<Input type="time" class="w-32" bind:value={time} aria-label="End time" disabled={busy} />
				<span class="text-muted-foreground text-xs">{zone}</span>
			</div>
			{#if latest}
				<p class="text-muted-foreground text-xs">The latest it can end is {formatDateTime(latest.toISOString())}.</p>
			{/if}
			<p class="text-muted-foreground min-h-5 text-sm" aria-live="polite">{problem ?? ''}</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="temp-extend-form" disabled={busy || problem !== null}>
				{busy ? 'Saving…' : 'Save'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
