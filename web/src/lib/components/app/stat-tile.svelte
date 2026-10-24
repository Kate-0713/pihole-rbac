<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	// One number with its label, inside a <dl>: the label is a <dt> and the value a <dd>, so screen readers read them
	// as a pair.
	let { label, value, detail }: { label: string; value: string; detail?: string } = $props();
</script>

<div class="bg-muted/40 grid gap-0.5 rounded-lg px-3 py-2">
	<dt class="text-muted-foreground text-xs">{label}</dt>
	<dd class="text-lg font-semibold tabular-nums">{value}</dd>
	{#if detail}
		<dd class="text-muted-foreground text-xs">{detail}</dd>
	{/if}
</div>
