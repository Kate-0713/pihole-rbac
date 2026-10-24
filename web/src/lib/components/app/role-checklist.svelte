<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import type { Role } from '#lib/roles.js';
	import { roleChoices } from '#lib/users.js';

	// A checkbox per role, for giving a user roles. A role holding grants the caller doesn't can't be given or taken
	// away by them, so its box is shown but locked. `selected` is bindable: the parent reads the ticked role IDs.
	let {
		selected = $bindable([]),
		roles,
		disabled = false
	}: { selected: number[]; roles: Role[]; disabled?: boolean } = $props();

	let choices = $derived(roleChoices(roles));

	function toggle(id: number, on: boolean) {
		// A new array rather than push/splice, so a parent holding a copy of the old list (to compare) isn't changed.
		selected = on ? [...selected, id] : selected.filter((x) => x !== id);
	}
</script>

<fieldset class="grid gap-2" {disabled}>
	<legend class="mb-2 text-sm font-medium">Roles</legend>
	{#if choices.length === 0}
		<p class="text-muted-foreground text-sm">There are no roles yet.</p>
	{/if}
	{#each choices as { role, selectable } (role.id)}
		<div class="flex items-start gap-2">
			<Checkbox
				id="role-{role.id}"
				class="mt-0.5"
				checked={selected.includes(role.id)}
				disabled={disabled || !selectable}
				onCheckedChange={(on) => toggle(role.id, on === true)}
				aria-describedby={role.description || !selectable ? `role-${role.id}-note` : undefined}
			/>
			<div class="grid gap-0.5">
				<Label for="role-{role.id}" class="font-normal">{role.name}</Label>
				{#if role.description || !selectable}
					<p id="role-{role.id}-note" class="text-muted-foreground text-xs">
						{role.description}{role.description && !selectable ? ' · ' : ''}{!selectable
							? "Holds permissions you don't, so you can't give or remove it."
							: ''}
					</p>
				{/if}
			</div>
		</div>
	{/each}
</fieldset>
