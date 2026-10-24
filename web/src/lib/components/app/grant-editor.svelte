<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { classLabel, scopeOptions, type Catalogue, type EditorState, type PermissionClass } from '#lib/roles.js';

	// The grant editor: one row per permission in the catalogue, grouped by class. A row's "All instances" covers
	// every scope; otherwise the instances and groups ticked are granted one by one.
	//
	// The parent passes its editor state with bind:state. Svelte 5's $state is deeply reactive, so ticking a box
	// changes the parent's object in place and whatever reads it (the Save button, say) updates. $bindable marks the
	// prop as one this component may change: Svelte 5 expects that to be declared, even for changes inside an object.
	let {
		state = $bindable(),
		catalogue,
		disabled = false
	}: { state: EditorState; catalogue: Catalogue; disabled?: boolean } = $props();

	const classes: PermissionClass[] = ['instance', 'group', 'global'];

	function toggle(list: number[], id: number, on: boolean) {
		const i = list.indexOf(id);
		if (on && i < 0) list.push(id);
		if (!on && i >= 0) list.splice(i, 1);
	}

	// Checkbox IDs must be unique on the page and valid in a selector, so dots in permission names are replaced.
	const idFor = (perm: string, part: string) => `grant-${perm.replaceAll('.', '-')}-${part}`;
</script>

<div class="grid gap-6">
	{#each classes as cls (cls)}
		{@const perms = catalogue.permissions.filter((p) => p.class === cls)}
		{#if perms.length > 0}
			<section class="grid gap-2" aria-labelledby="grants-{cls}">
				<h3 id="grants-{cls}" class="text-sm font-semibold">{classLabel[cls]}</h3>
				{#if cls === 'group' && catalogue.groups.every((g) => g.mode !== 'mirrored')}
					<p class="text-muted-foreground text-sm">
						There are no mirrored groups yet, so these can only be granted on all of them, including any added later.
					</p>
				{/if}
				<div class="divide-y rounded-md border">
					{#each perms as p (p.name)}
						{@const row = state[p.name]}
						{@const options = scopeOptions(p, catalogue)}
						<div class="grid gap-2 p-3 sm:grid-cols-[minmax(0,14rem)_1fr]">
							<div>
								<p class="font-mono text-sm">{p.name}</p>
								<p class="text-muted-foreground text-xs">{p.description}</p>
							</div>
							<!-- role="group" with a label lets a screen reader say which permission each box belongs to. -->
							<div class="flex flex-wrap items-center gap-x-4 gap-y-2" role="group" aria-label={p.name}>
								<div class="flex items-center gap-2">
									<Checkbox id={idFor(p.name, 'all')} bind:checked={row.all} {disabled} />
									<Label for={idFor(p.name, 'all')} class="font-normal">
										{cls === 'global' ? 'Granted' : cls === 'group' ? 'All mirrored groups' : 'All instances'}
									</Label>
								</div>
								{#each options.instances as inst (inst.id)}
									<div class="flex items-center gap-2" class:opacity-50={row.all}>
										<Checkbox
											id={idFor(p.name, `i${inst.id}`)}
											checked={row.all || row.instances.includes(inst.id)}
											disabled={disabled || row.all}
											onCheckedChange={(on) => toggle(row.instances, inst.id, on === true)}
										/>
										<Label for={idFor(p.name, `i${inst.id}`)} class="font-normal">{inst.name}</Label>
									</div>
								{/each}
								{#each options.groups as group (group.id)}
									<div class="flex items-center gap-2" class:opacity-50={row.all}>
										<Checkbox
											id={idFor(p.name, `g${group.id}`)}
											checked={row.all || row.groups.includes(group.id)}
											disabled={disabled || row.all}
											onCheckedChange={(on) => toggle(row.groups, group.id, on === true)}
										/>
										<Label for={idFor(p.name, `g${group.id}`)} class="font-normal">group {group.name}</Label>
									</div>
								{/each}
							</div>
						</div>
					{/each}
				</div>
			</section>
		{/if}
	{/each}
</div>
