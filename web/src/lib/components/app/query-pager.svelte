<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ChevronLeftIcon from '@lucide/svelte/icons/chevron-left';
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import ChevronsLeftIcon from '@lucide/svelte/icons/chevrons-left';
	import ChevronsRightIcon from '@lucide/svelte/icons/chevrons-right';
	import { goto } from '$app/navigation';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { pageWindow } from '#lib/queries.js';

	// The pager for numbered pages. href gives a page's link, so every control is a plain link that Back undoes.
	// pages is how many can be reached; capped means more entries match than that (a mirrored group's merged log),
	// so there is no Last.
	let { page, pages, capped, href }: { page: number; pages: number; capped: boolean; href: (page: number) => string } =
		$props();

	let jump = $state('');
	let jumpProblem = $derived.by(() => {
		if (jump.trim() === '') return null;
		const n = Number(jump);
		return Number.isInteger(n) && n >= 1 && n <= pages ? null : `Pick a page from 1 to ${pages}.`;
	});

	function go(event: SubmitEvent) {
		event.preventDefault();
		if (jump.trim() === '' || jumpProblem) return;
		const n = Number(jump);
		jump = '';
		void goto(href(n));
	}
</script>

{#if pages > 1 || page > 1}
	<nav class="flex flex-wrap items-center gap-1" aria-label="Pages">
		<Button variant="outline" size="sm" href={page > 1 ? href(1) : undefined} disabled={page <= 1} aria-label="First page">
			<ChevronsLeftIcon />
		</Button>
		<Button
			variant="outline"
			size="sm"
			href={page > 1 ? href(Math.min(page - 1, Math.max(pages, 1))) : undefined}
			disabled={page <= 1}
			aria-label="Previous page"
		>
			<ChevronLeftIcon />
		</Button>
		{#each pageWindow(page, pages) as p, i (i)}
			{#if p === null}
				<span class="text-muted-foreground px-1 text-sm" aria-hidden="true">…</span>
			{:else}
				<Button
					variant={p === page ? 'default' : 'ghost'}
					size="sm"
					href={href(p)}
					aria-label="Page {p}"
					aria-current={p === page ? 'page' : undefined}
					class="tabular-nums">{p}</Button
				>
			{/if}
		{/each}
		<Button variant="outline" size="sm" href={page < pages ? href(page + 1) : undefined} disabled={page >= pages} aria-label="Next page">
			<ChevronRightIcon />
		</Button>
		{#if !capped}
			<Button variant="outline" size="sm" href={page !== pages && pages > 0 ? href(pages) : undefined} disabled={page === pages || pages === 0} aria-label="Last page">
				<ChevronsRightIcon />
			</Button>
		{/if}
		{#if pages > 1}
			<form class="ml-2 flex items-center gap-1" onsubmit={go}>
				<label for="query-jump" class="text-muted-foreground text-xs">Go to page</label>
				<Input
					id="query-jump"
					class="h-8 w-20"
					inputmode="numeric"
					bind:value={jump}
					aria-invalid={jumpProblem ? 'true' : undefined}
					aria-describedby={jumpProblem ? 'query-jump-problem' : undefined}
				/>
				<Button type="submit" variant="outline" size="sm" disabled={jump.trim() === '' || !!jumpProblem}>Go</Button>
				{#if jumpProblem}<span id="query-jump-problem" class="text-destructive text-xs">{jumpProblem}</span>{/if}
			</form>
		{/if}
	</nav>
{/if}
