<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	// Wraps text that can be any length (domains, names, group lists, comments) inside a table cell, so one long value
	// grows the row downwards instead of pushing the rest of the table off the side of the screen.
	//
	// Table cells default to whitespace-nowrap (see ui/table/table-cell.svelte), which suits dates, badges and buttons.
	// This turns wrapping back on for its contents and gives them a width range: the column never gets narrower than
	// the minimum or wider than the maximum. wrap-anywhere (CSS overflow-wrap: anywhere) prefers to break at spaces
	// and only splits a word, such as a long domain, when the word alone is wider than the column. Unlike
	// break-words it also lets the table count the column as narrow when sharing out space, which is what stops a long
	// value forcing its column wide. The width lives on this <div> rather than on the <td>, because browsers don't
	// reliably honour max-width on a table cell.
	import type { Snippet } from 'svelte';
	import { cn } from '#lib/utils.js';

	type Width = 'sm' | 'md' | 'lg';

	let { width = 'md', class: className, children }: { width?: Width; class?: string; children: Snippet } = $props();

	// Whole class names, not built from parts: Tailwind finds the classes to generate by scanning the source for them
	// as written, so `max-w-${n}` would never be generated.
	const widths: Record<Width, string> = {
		sm: 'min-w-24 max-w-48',
		md: 'min-w-32 max-w-64',
		lg: 'min-w-40 max-w-80'
	};
</script>

<div class={cn('wrap-anywhere whitespace-normal', widths[width], className)}>
	{@render children()}
</div>
