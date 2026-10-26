<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import MonitorIcon from '@lucide/svelte/icons/monitor';
	import MoonIcon from '@lucide/svelte/icons/moon';
	import SunIcon from '@lucide/svelte/icons/sun';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { parseChoice, theme } from '#lib/stores/theme.svelte.js';

	// Light, dark, or follow the system. The choice is kept in this browser; see stores/theme.svelte.ts.
	const labels = { light: 'Light', dark: 'Dark', system: 'System' } as const;
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="ghost" size="icon-sm" aria-label="Theme: {labels[theme.choice]}">
				{#if theme.choice === 'system'}
					<MonitorIcon />
				{:else if theme.choice === 'dark'}
					<MoonIcon />
				{:else}
					<SunIcon />
				{/if}
			</Button>
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end">
		<DropdownMenu.Label class="text-muted-foreground text-xs font-normal">Theme</DropdownMenu.Label>
		<!-- A radio group: bits-ui gives each item the menuitemradio role and marks the chosen one. The shadcn item
		     keeps the menu open after a pick by default; here a pick is the whole job, so it closes. -->
		<DropdownMenu.RadioGroup value={theme.choice} onValueChange={(v) => theme.set(parseChoice(v))}>
			<DropdownMenu.RadioItem value="light" closeOnSelect><SunIcon />Light</DropdownMenu.RadioItem>
			<DropdownMenu.RadioItem value="dark" closeOnSelect><MoonIcon />Dark</DropdownMenu.RadioItem>
			<DropdownMenu.RadioItem value="system" closeOnSelect><MonitorIcon />System</DropdownMenu.RadioItem>
		</DropdownMenu.RadioGroup>
	</DropdownMenu.Content>
</DropdownMenu.Root>
