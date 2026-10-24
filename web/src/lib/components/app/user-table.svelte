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
	import { formatDateTime } from '#lib/format.js';
	import { isSelf, rolesSummary, sourceLabel, userActions, type User } from '#lib/users.js';

	// A plain table sorted by username, which the server already does: an install has a handful of users.
	let {
		users,
		selfID,
		busy,
		onroles,
		onpassword,
		onenable,
		ondisable,
		ondelete
	}: {
		users: User[];
		selfID: number | undefined;
		// The ID of the user an enable is running on, so its menu can't start another one.
		busy: number | null;
		onroles: (u: User) => void;
		onpassword: (u: User) => void;
		onenable: (u: User) => void;
		ondisable: (u: User) => void;
		ondelete: (u: User) => void;
	} = $props();
</script>

<!-- On a phone the table scrolls sideways inside its own box rather than widening the page. -->
<div class="overflow-x-auto rounded-md border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				<Table.Head>Username</Table.Head>
				<Table.Head>Account</Table.Head>
				<Table.Head>Roles</Table.Head>
				<Table.Head>Status</Table.Head>
				<Table.Head>Last login</Table.Head>
				<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each users as u (u.id)}
				{@const self = isSelf(u, selfID)}
				{@const can = userActions(u)}
				<Table.Row>
					<Table.Cell>
						<span class="font-medium">{u.username}</span>
						{#if self}<Badge variant="secondary" class="ml-1">You</Badge>{/if}
						{#if !u.manageable}
							<p class="text-muted-foreground text-xs">Holds permissions you don't, so you can't change it.</p>
						{/if}
					</Table.Cell>
					<Table.Cell>
						{sourceLabel(u)}
						{#if u.ldap_dn}
							<p class="text-muted-foreground max-w-64 font-mono text-xs break-all">{u.ldap_dn}</p>
						{/if}
					</Table.Cell>
					<!-- class: directives only work on plain elements, so a component gets a class expression instead. -->
					<Table.Cell class={u.roles.length === 0 ? 'text-muted-foreground' : ''}>{rolesSummary(u)}</Table.Cell>
					<Table.Cell>
						{#if u.disabled}
							<Badge variant="destructive">Disabled</Badge>
						{:else}
							<Badge variant="secondary">Enabled</Badge>
						{/if}
					</Table.Cell>
					<Table.Cell class="whitespace-nowrap">
						{u.last_login_at ? formatDateTime(u.last_login_at) : 'Never'}
					</Table.Cell>
					<Table.Cell>
						{#if u.manageable}
							<DropdownMenu.Root>
								<DropdownMenu.Trigger>
									{#snippet child({ props })}
										<Button
											{...props}
											variant="ghost"
											size="icon"
											disabled={busy === u.id}
											aria-label="Actions for {u.username}"
										>
											<EllipsisIcon />
										</Button>
									{/snippet}
								</DropdownMenu.Trigger>
								<DropdownMenu.Content align="end">
									{#if can.roles}
										<DropdownMenu.Item onSelect={() => onroles(u)}>Change roles</DropdownMenu.Item>
									{/if}
									{#if can.password}
										<!-- Your own password is changed from the account menu, which asks for the current one. -->
										{#if !self}
											<DropdownMenu.Item onSelect={() => onpassword(u)}>Set password</DropdownMenu.Item>
										{/if}
									{/if}
									{#if u.disabled}
										<DropdownMenu.Item onSelect={() => onenable(u)}>Enable</DropdownMenu.Item>
									{:else}
										<DropdownMenu.Item onSelect={() => ondisable(u)}>Disable</DropdownMenu.Item>
									{/if}
									<DropdownMenu.Separator />
									<DropdownMenu.Item variant="destructive" onSelect={() => ondelete(u)}>Delete</DropdownMenu.Item>
								</DropdownMenu.Content>
							</DropdownMenu.Root>
						{/if}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
