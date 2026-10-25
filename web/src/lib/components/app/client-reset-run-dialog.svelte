<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { untrack } from 'svelte';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import ClientResetResults from '#lib/components/app/client-reset-results.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { describePreview, describeRun, runCounts, runStatusLabel, type Preview, type Run } from '#lib/clientreset.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Running a target's client reset rules. Opening the dialog reads a preview (a dry run: what would change, without
	// changing anything), so the person running it sees the actual clients first, as v1's confirmation prompt did
	// without the list. After the run, the dialog shows what happened on each instance.
	let {
		open = $bindable(false),
		target,
		name,
		onran
	}: { open: boolean; target: string; name: string; onran: () => Promise<void> | void } = $props();

	let preview = $state<Preview | null>(null);
	let run = $state<Run | null>(null);
	let error = $state<string | null>(null);
	let loading = $state(false);
	let running = $state(false);

	async function readPreview() {
		loading = true;
		try {
			preview = await unwrap(api.GET('/api/v1/targets/{target}/client-reset/preview', { params: { path: { target } } }));
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			loading = false;
		}
	}

	// Each time the dialog opens, it starts again with a fresh preview. The effect depends on `open` alone: the rest
	// runs inside untrack, so reading `target` doesn't make it a dependency too. That matters because a prop passed as
	// `target={data.target}` is read through the parent's `data`, which the dashboard replaces on every refresh (a run
	// triggers one): without untrack, the refresh after a run would clear the run's results and read a new preview.
	// readPreview isn't awaited: an $effect's function can't be async, and what it sets is shown as it arrives.
	$effect(() => {
		if (!open) return;
		untrack(() => {
			preview = null;
			run = null;
			error = null;
			void readPreview();
		});
	});

	let counts = $derived(preview ? runCounts(preview.instances) : null);

	async function start() {
		running = true;
		error = null;
		try {
			run = await unwrap(api.POST('/api/v1/targets/{target}/client-reset/run', { params: { path: { target } } }));
			const summary = describeRun(run);
			if (run.status === 'ok') notices.success(`Client reset on ${name}: ${summary.toLowerCase()}.`);
			else notices.error(summary, `Client reset on ${name} ${run.status === 'partial' ? 'partly worked' : 'failed'}`);
			await onran();
		} catch (e) {
			// Another run in progress, no rules any more, or the instance disabled meanwhile: nothing was changed.
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			running = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
		<Dialog.Header>
			<Dialog.Title>{run ? 'Client reset done' : 'Run client reset'}</Dialog.Title>
			<Dialog.Description>
				{#if run}
					On {name}: {describeRun(run)}.
				{:else}
					Puts the clients the rules match on {name} back in their Pi-hole groups now.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-3" aria-live="polite">
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			{#if run}
				<p class="flex items-center gap-2 text-sm">
					<Badge variant={run.status === 'ok' ? 'secondary' : run.status === 'failed' ? 'destructive' : 'outline'}>
						{runStatusLabel[run.status]}
					</Badge>
					<span class="text-muted-foreground text-xs">Run #{run.id}</span>
				</p>
				<ClientResetResults instances={run.instances} />
			{:else if loading}
				<p class="text-muted-foreground text-sm">Checking what would change…</p>
			{:else if preview}
				<p class="text-sm">{describePreview(preview)}</p>
				<ClientResetResults instances={preview.instances} preview />
				{#if counts && counts.unread > 0}
					<p class="text-sm text-amber-700 dark:text-amber-400">
						Some instances couldn't be read, so the run may not reach them either.
					</p>
				{/if}
			{/if}
		</div>

		<Dialog.Footer>
			{#if run}
				<Button onclick={() => (open = false)}>OK</Button>
			{:else}
				<Button variant="outline" onclick={() => (open = false)} disabled={running}>Cancel</Button>
				<Button onclick={start} disabled={running || loading || preview === null}>
					{running ? 'Running…' : 'Run now'}
				</Button>
			{/if}
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
