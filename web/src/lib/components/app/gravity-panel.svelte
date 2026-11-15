<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import XIcon from '@lucide/svelte/icons/x';
	import { untrack } from 'svelte';
	import { api, unwrap } from '#lib/api/client.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { mergeOutput, resultLabel, resultText, runSummary, type GravityLine, type GravityRun } from '#lib/lists.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Follows a gravity run: its members' results, and its output as it arrives. The page passes the run it started,
	// or the target's latest when it loads during one; the panel polls the run about once a second until it's done,
	// then calls ondone with the finished run, so the page can say gravity has stopped running and read the lists
	// again (their status has changed). Closing it hides it (`hidden`) without stopping the polling, so the page still
	// hears when the run ends.
	let {
		target,
		run,
		hidden = false,
		ondone,
		onclose
	}: {
		target: string;
		run: GravityRun;
		hidden?: boolean;
		ondone: (run: GravityRun) => Promise<void> | void;
		onclose: () => void;
	} = $props();

	let current = $state<GravityRun | null>(null);
	let lines = $state<GravityLine[]>([]);
	let failed = $state<string | null>(null);
	let box = $state<HTMLElement | null>(null);
	// Whether the output box is scrolled to the bottom, so new lines keep it there; scrolled up, it stays put.
	let following = $state(true);

	// A new run (another id) starts the panel afresh. The effect depends on runId alone: a $derived only tells its
	// readers when its value changes, so the page handing back the same run, finished, doesn't restart the panel and
	// lose its output. untrack reads the run without depending on it.
	let runId = $derived(run.id);
	$effect(() => {
		const id = runId;
		const first = untrack(() => run);
		current = first;
		lines = mergeOutput([], first);
		failed = null;
		if (first.status === 'done') return;
		let stopped = false;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const poll = async () => {
			try {
				const after = lines.at(-1)?.seq ?? 0;
				const next = await unwrap(
					api.GET('/api/v1/targets/{target}/gravity/{run}', { params: { path: { target, run: id }, query: { after } } })
				);
				if (stopped) return;
				current = next;
				lines = mergeOutput(lines, next);
				failed = null;
				if (next.status === 'done') {
					const s = runSummary(next);
					if (s.ok) notices.success(s.text);
					else notices.error(s.text, 'Gravity didn\'t finish everywhere');
					await ondone(next);
					return;
				}
			} catch (e) {
				if (stopped) return;
				// A failed poll (the app restarting, say) is retried; the run itself carries on.
				failed = e instanceof Error ? e.message : 'The run couldn\'t be read.';
			}
			timer = setTimeout(poll, 1000);
		};
		timer = setTimeout(poll, 500);
		return () => {
			stopped = true;
			if (timer !== undefined) clearTimeout(timer);
		};
	});

	// Keep the newest line in view while following. $effect.pre would run before the DOM updates; a plain $effect runs
	// after, when the new lines are on screen.
	$effect(() => {
		void lines.length;
		if (box && following) box.scrollTop = box.scrollHeight;
	});
	function scrolled() {
		if (box) following = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
	}

	let names = $derived(new Map((current?.results ?? []).map((r) => [r.instance_id, r.instance])));
	let several = $derived((current?.results.length ?? 0) > 1);
	const tone = { pending: 'outline', running: 'secondary', ok: 'secondary', failed: 'destructive', skipped: 'outline' } as const;
</script>

{#if current}
	<Card.Root role="region" aria-labelledby="gravity-title" {hidden}>
		<Card.Header class="flex flex-row items-start justify-between gap-2">
			<div class="grid gap-1">
				<Card.Title class="flex flex-wrap items-center gap-2">
					<h2 id="gravity-title">Gravity update</h2>
					<Badge variant={current.status === 'done' ? 'outline' : 'secondary'}>
						{current.status === 'done' ? 'Finished' : 'Running'}
					</Badge>
				</Card.Title>
				<Card.Description>
					Started {formatDateTime(current.started_at)} by {current.started_by}{current.finished_at
						? `, finished ${formatDateTime(current.finished_at)}`
						: ''}.
					{#if several}Members are updated one at a time, the primary first; a failure stops the rest.{/if}
					Pi-hole keeps blocking with its old lists until the update is done.
				</Card.Description>
			</div>
			<Button variant="ghost" size="icon" aria-label="Close the gravity panel" onclick={onclose}>
				<XIcon />
			</Button>
		</Card.Header>
		<Card.Content class="grid gap-3">
			<ul class="grid gap-1.5 text-sm" aria-label="Instances" aria-live="polite">
				{#each current.results as r (r.instance_id)}
					<li class="flex flex-wrap items-baseline gap-x-2" data-instance={r.instance}>
						<span class="font-medium">{r.instance}</span>
						{#if r.primary}<Badge variant="outline">Primary</Badge>{/if}
						<Badge variant={tone[r.status]}>{resultLabel[r.status]}</Badge>
						<span class={r.status === 'failed' ? 'text-destructive' : 'text-muted-foreground'}>{resultText(r)}</span>
					</li>
				{/each}
			</ul>
			{#if failed}
				<p class="text-muted-foreground text-xs">Couldn't read the run just now ({failed}). Trying again…</p>
			{/if}
			<!-- Lines are shown as text, never as HTML: they come from Pi-hole. -->
			<div
				bind:this={box}
				onscroll={scrolled}
				class="bg-muted max-h-80 overflow-y-auto rounded-md p-3 font-mono text-xs leading-relaxed"
				role="log"
				aria-label="Gravity output"
			>
				{#each lines as l, i (l.seq === 0 ? `gap-${i}` : l.seq)}
					<div class="break-all whitespace-pre-wrap {l.seq === 0 ? 'text-muted-foreground italic' : ''}">
						{#if several && l.seq !== 0}<span class="text-muted-foreground">{names.get(l.instance_id)}: </span>{/if}{l.text}
					</div>
				{:else}
					<p class="text-muted-foreground">No output yet.</p>
				{/each}
			</div>
		</Card.Content>
	</Card.Root>
{/if}
