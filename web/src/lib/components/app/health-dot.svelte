<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import type { Target } from '#lib/stores/targets.svelte.js';

	let { health }: { health: Target['health'] } = $props();

	const looks = {
		up: { dot: 'bg-emerald-500', label: 'Up' },
		down: { dot: 'bg-red-500', label: 'Down' },
		// Only a mirrored group: some of its members are up and some aren't.
		degraded: { dot: 'bg-amber-500', label: 'Some members down' },
		unknown: { dot: 'bg-muted-foreground/40', label: 'Not checked yet' }
	} as const;

	let state = $derived(looks[health?.state ?? 'unknown']);
</script>

<!-- Colour alone doesn't carry meaning: the label is there for screen readers and as a tooltip. -->
<span class="inline-block size-2 shrink-0 rounded-full {state.dot}" title={state.label} aria-hidden="true"></span>
<span class="sr-only">{state.label}</span>
