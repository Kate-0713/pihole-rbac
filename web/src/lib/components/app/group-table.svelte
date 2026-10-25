<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { modeLabel, sortedMembers, type Group } from '#lib/groups.js';

	// A plain table, sorted by name, like the instances table: an install has a handful of groups.
	let { groups, onedit, ondelete }: { groups: Group[]; onedit: (g: Group) => void; ondelete: (g: Group) => void } =
		$props();

	let sorted = $derived([...groups].sort((a, b) => a.name.localeCompare(b.name)));
</script>

<div class="overflow-x-auto rounded-md border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				<Table.Head>Name</Table.Head>
				<Table.Head>Mode</Table.Head>
				<Table.Head>Members</Table.Head>
				<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each sorted as g (g.id)}
				<Table.Row>
					<Table.Cell class="font-medium">{g.name}</Table.Cell>
					<Table.Cell>
						<Badge variant={g.mode === 'mirrored' ? 'default' : 'secondary'}>{modeLabel[g.mode]}</Badge>
					</Table.Cell>
					<Table.Cell class="whitespace-normal">
						{#if g.members.length === 0}
							<span class="text-muted-foreground text-sm">No members</span>
						{:else}
							<ul class="flex flex-wrap gap-1" aria-label="Members of {g.name}">
								{#each sortedMembers(g) as m (m.id)}
									<li>
										<Badge variant="outline" class={m.enabled ? '' : 'text-muted-foreground'}>
											{m.name}{m.id === g.primary_instance_id ? ' · primary' : ''}{m.enabled ? '' : ' · disabled'}
										</Badge>
									</li>
								{/each}
							</ul>
						{/if}
					</Table.Cell>
					<Table.Cell>
						<DropdownMenu.Root>
							<DropdownMenu.Trigger>
								{#snippet child({ props })}
									<Button {...props} variant="ghost" size="icon" aria-label="Actions for {g.name}">
										<EllipsisIcon />
									</Button>
								{/snippet}
							</DropdownMenu.Trigger>
							<DropdownMenu.Content align="end">
								<DropdownMenu.Item onSelect={() => onedit(g)}>Edit</DropdownMenu.Item>
								<DropdownMenu.Separator />
								<DropdownMenu.Item variant="destructive" onSelect={() => ondelete(g)}>Delete</DropdownMenu.Item>
							</DropdownMenu.Content>
						</DropdownMenu.Root>
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
