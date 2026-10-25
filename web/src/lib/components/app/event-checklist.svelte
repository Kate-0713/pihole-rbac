<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { groupEvents, type NotificationEvent } from '#lib/notifications.js';

	// The events a channel receives, a checkbox each, under the server's groups; each group has a box that ticks or
	// clears the whole group. `selected` is bindable: the parent reads the ticked event names.
	let { selected = $bindable([]), events }: { selected: string[]; events: NotificationEvent[] } = $props();

	let groups = $derived(groupEvents(events));

	function toggle(name: string, on: boolean) {
		selected = on ? [...selected, name] : selected.filter((x) => x !== name);
	}

	function toggleGroup(names: string[], on: boolean) {
		const rest = selected.filter((x) => !names.includes(x));
		selected = on ? [...rest, ...names] : rest;
	}

	// A group's box: ticked when all its events are, half-ticked when some are.
	function groupState(names: string[]): { checked: boolean; indeterminate: boolean } {
		const n = names.filter((x) => selected.includes(x)).length;
		return { checked: n === names.length, indeterminate: n > 0 && n < names.length };
	}
</script>

<fieldset class="grid gap-4">
	<legend class="mb-1 text-sm font-medium">Events ({selected.length} chosen)</legend>
	{#each groups as g, gi (g.group)}
		{@const names = g.events.map((e) => e.name)}
		{@const state = groupState(names)}
		<div class="grid gap-2 rounded-md border p-3">
			<div class="flex items-center gap-2">
				<Checkbox
					id="event-group-{gi}"
					checked={state.checked}
					indeterminate={state.indeterminate}
					onCheckedChange={(on) => toggleGroup(names, on === true)}
				/>
				<Label for="event-group-{gi}">{g.group}</Label>
			</div>
			<div class="grid gap-2 pl-6 sm:grid-cols-2">
				{#each g.events as e (e.name)}
					<div class="flex items-start gap-2">
						<Checkbox
							id="event-{e.name}"
							class="mt-0.5"
							checked={selected.includes(e.name)}
							onCheckedChange={(on) => toggle(e.name, on === true)}
							aria-describedby="event-{e.name}-note"
						/>
						<div class="grid min-w-0 gap-0.5">
							<Label for="event-{e.name}" class="font-mono text-xs font-normal">{e.name}</Label>
							<p id="event-{e.name}-note" class="text-muted-foreground text-xs">{e.description}</p>
						</div>
					</div>
				{/each}
			</div>
		</div>
	{/each}
</fieldset>
