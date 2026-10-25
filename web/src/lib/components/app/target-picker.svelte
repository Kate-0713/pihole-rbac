<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import * as Select from '#lib/components/ui/select/index.js';
	import { can } from '#lib/permissions.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { targets } from '#lib/stores/targets.svelte.js';
	import HealthDot from './health-dot.svelte';

	let { current }: { current: string | null } = $props();

	let selected = $derived(targets.find(current));
	let instances = $derived(targets.list.filter((t) => t.kind === 'instance'));
	let groups = $derived(targets.list.filter((t) => t.kind === 'group'));

	// Choosing a target stays on the same page and only changes ?target=, which reruns the page's load functions.
	// reset: false keeps the scroll position and focus where they were (SvelteKit 3's replacement for keepFocus and
	// noScroll). page.url is read-only, so the new URL is built from a copy.
	function choose(id: string) {
		if (id === current) return;
		const url = new URL(page.url.href);
		url.searchParams.set('target', id);
		void goto(url.pathname + url.search, { reset: false });
	}

	// The health beside each name changes over time, so the list is fetched again whenever the picker opens.
	function opened(open: boolean) {
		if (open) targets.refresh().catch((e: unknown) => notices.error(e, "Couldn't refresh your instances"));
	}
</script>

{#if targets.list.length === 0}
	<span class="text-muted-foreground text-sm">
		{#if can('instances.manage')}
			No instances yet. <a class="underline underline-offset-4" href="/admin/instances">Add one</a>
		{:else}
			No instances available
		{/if}
	</span>
{:else}
	<!-- bits-ui's Select: `value` is the selected item's value; onValueChange fires when the user picks another. -->
	<Select.Root type="single" value={current ?? undefined} onValueChange={choose} onOpenChange={opened}>
		<Select.Trigger class="w-56" aria-label={groups.length > 0 ? 'Instance or group' : 'Instance'}>
			{#if selected}
				<span class="flex items-center gap-2 truncate">
					<HealthDot health={selected.health} />
					<span class="truncate">{selected.name}</span>
				</span>
			{:else}
				Choose an instance
			{/if}
		</Select.Trigger>
		<Select.Content>
			<!-- Instances, then mirrored groups, each under a heading once there are both. -->
			{#each [{ heading: 'Instances', items: instances }, { heading: 'Mirrored groups', items: groups }] as section (section.heading)}
				{#if section.items.length > 0}
					<Select.Group>
						{#if groups.length > 0}
							<Select.GroupHeading>{section.heading}</Select.GroupHeading>
						{/if}
						{#each section.items as t (t.id)}
							<Select.Item value={t.id} label={t.name}>
								<HealthDot health={t.health} />
								<!-- No whitespace after the name: an instance's option reads exactly "<health> <name>". -->
								<span class="truncate">{t.name}</span>{#if t.members}<span class="text-muted-foreground ml-auto text-xs"
										>{t.members.length === 1 ? '1 member' : `${t.members.length} members`}</span
									>{/if}
							</Select.Item>
						{/each}
					</Select.Group>
				{/if}
			{/each}
		</Select.Content>
	</Select.Root>
{/if}
