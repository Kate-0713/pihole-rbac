<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
	import { api, unwrap, type Schemas } from '#lib/api/client.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { formatCountdown, formatDuration } from '#lib/format.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';

	type BlockingStatus = Schemas['BlockingStatus'];

	let {
		target,
		status,
		fetchedAt,
		canToggle,
		onchange
	}: {
		target: string;
		status: BlockingStatus;
		// When status was read, so the countdown can run from it.
		fetchedAt: number;
		canToggle: boolean;
		// Called after a change was attempted, whatever its result, so the page reads the status again.
		onchange: () => Promise<void> | void;
	} = $props();

	// How long to turn blocking off for, as in Pi-hole's own menu. null means until someone turns it back on.
	const durations: { seconds: number | null; label: string }[] = [
		{ seconds: 30, label: 'For 30 seconds' },
		{ seconds: 300, label: 'For 5 minutes' },
		{ seconds: 1800, label: 'For 30 minutes' },
		{ seconds: 3600, label: 'For 1 hour' },
		{ seconds: null, label: 'Until turned back on' }
	];

	let busy = $state(false);

	// The countdown ticks once a second, but only while a timer is running. $effect reruns when what it reads
	// (status.timer here) changes, and the function it returns cleans up before that and when the component goes.
	let now = $state(Date.now());
	$effect(() => {
		if (!status.timer) return;
		now = Date.now();
		const tick = setInterval(() => (now = Date.now()), 1000);
		return () => clearInterval(tick);
	});
	let remaining = $derived(status.timer ? status.timer - (now - fetchedAt) / 1000 : null);

	async function set(enabled: boolean, seconds: number | null = null) {
		busy = true;
		const text = enabled
			? { done: 'Blocking turned on', failed: "Couldn't turn blocking on" }
			: {
					done: seconds ? `Blocking turned off for ${formatDuration(seconds)}` : 'Blocking turned off',
					failed: "Couldn't turn blocking off"
				};
		try {
			const body = seconds ? { enabled, timer: seconds } : { enabled };
			const { results } = await unwrap(
				api.PUT('/api/v1/targets/{target}/blocking', { params: { path: { target } }, body })
			);
			reportResults(results, text);
		} catch (e) {
			reportFailure(e, text);
		} finally {
			await onchange();
			busy = false;
		}
	}
</script>

<div class="grid gap-3">
	<p class="flex items-center gap-2 font-medium" aria-live="polite">
		{#if status.blocking === 'enabled'}
			<span class="size-2.5 rounded-full bg-emerald-500" aria-hidden="true"></span>
			Blocking is on
		{:else if status.blocking === 'disabled'}
			<span class="size-2.5 rounded-full bg-amber-500" aria-hidden="true"></span>
			Blocking is off
			{#if remaining !== null}
				<span class="text-muted-foreground font-normal">· back on in {formatCountdown(remaining)}</span>
			{/if}
		{:else}
			<span class="bg-muted-foreground/40 size-2.5 rounded-full" aria-hidden="true"></span>
			Pi-hole couldn't tell whether blocking is on
		{/if}
	</p>

	{#if canToggle}
		<div class="flex flex-wrap gap-2">
			{#if status.blocking !== 'enabled'}
				<Button size="sm" disabled={busy} onclick={() => set(true)}>Turn blocking on</Button>
			{/if}
			{#if status.blocking !== 'disabled' || status.timer}
				<!-- Also offered while a timer runs, to change how long it stays off. -->
				<DropdownMenu.Root>
					<DropdownMenu.Trigger disabled={busy}>
						{#snippet child({ props })}
							<Button {...props} size="sm" variant="outline">
								{status.blocking === 'disabled' ? 'Change how long' : 'Turn blocking off'}
								<ChevronDownIcon />
							</Button>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="start">
						{#each durations as d (d.label)}
							<DropdownMenu.Item onSelect={() => set(false, d.seconds)}>{d.label}</DropdownMenu.Item>
						{/each}
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			{/if}
		</div>
	{/if}
</div>
