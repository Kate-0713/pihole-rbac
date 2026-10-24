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
	import { errorLabel, instanceStatus, passwordSummary, type Instance } from '#lib/instances.js';

	// A plain table rather than TanStack: an install has a handful of instances, so sorting by name is enough.
	let {
		instances,
		busy,
		onedit,
		onpassword,
		ontest,
		onenable,
		ondisable,
		ondelete
	}: {
		instances: Instance[];
		// The ID of the instance an action is running on, so its menu can't start another one.
		busy: number | null;
		onedit: (inst: Instance) => void;
		onpassword: (inst: Instance) => void;
		ontest: (inst: Instance) => void;
		onenable: (inst: Instance) => void;
		ondisable: (inst: Instance) => void;
		ondelete: (inst: Instance) => void;
	} = $props();

	let sorted = $derived([...instances].sort((a, b) => a.name.localeCompare(b.name)));

	const tones = {
		ok: 'bg-emerald-500',
		bad: 'bg-red-500',
		muted: 'bg-muted-foreground/40'
	} as const;
</script>

<!-- On a phone the table scrolls sideways inside its own box rather than widening the page. -->
<div class="overflow-x-auto rounded-md border">
	<Table.Root>
		<Table.Header>
			<Table.Row>
				<Table.Head>Name</Table.Head>
				<Table.Head>Address</Table.Head>
				<Table.Head>Status</Table.Head>
				<Table.Head>Password</Table.Head>
				<Table.Head class="w-0"><span class="sr-only">Actions</span></Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each sorted as inst (inst.id)}
				{@const status = instanceStatus(inst)}
				{@const lastError = inst.enabled ? errorLabel(inst.health?.last_error) : null}
				{@const pw = passwordSummary(inst)}
				<Table.Row>
					<Table.Cell class="font-medium">{inst.name}</Table.Cell>
					<Table.Cell>
						<span class="font-mono text-sm break-all">{inst.base_url}</span>
						{#if inst.tls_mode === 'insecure'}
							<Badge variant="outline" class="ml-1">TLS not verified</Badge>
						{/if}
					</Table.Cell>
					<Table.Cell>
						<span class="inline-flex items-center gap-2 whitespace-nowrap">
							<span class="inline-block size-2 shrink-0 rounded-full {tones[status.tone]}" aria-hidden="true"></span>
							{status.label}
						</span>
						{#if lastError && status.label !== 'Up'}
							<p class="text-muted-foreground text-xs">{lastError}</p>
						{:else if inst.enabled && inst.health?.last_success}
							<p class="text-muted-foreground text-xs">
								Last answered {formatDateTime(inst.health.last_success)}
							</p>
						{/if}
					</Table.Cell>
					<Table.Cell>
						<Badge variant={pw.tone === 'ok' ? 'secondary' : 'destructive'}>{pw.label}</Badge>
						{#if pw.detail}
							<p
								class="text-muted-foreground text-xs break-all"
								class:font-mono={inst.password_source === 'environment'}
							>
								{pw.detail}
							</p>
						{/if}
					</Table.Cell>
					<Table.Cell>
						<DropdownMenu.Root>
							<DropdownMenu.Trigger>
								{#snippet child({ props })}
									<Button
										{...props}
										variant="ghost"
										size="icon"
										disabled={busy === inst.id}
										aria-label="Actions for {inst.name}"
									>
										<EllipsisIcon />
									</Button>
								{/snippet}
							</DropdownMenu.Trigger>
							<DropdownMenu.Content align="end">
								<DropdownMenu.Item onSelect={() => ontest(inst)}>Test connection</DropdownMenu.Item>
								<DropdownMenu.Item onSelect={() => onedit(inst)}>Edit</DropdownMenu.Item>
								<!-- A password from the environment overrides a stored one, so it is changed there. -->
								{#if inst.password_source !== 'environment'}
									<DropdownMenu.Item onSelect={() => onpassword(inst)}>Change password</DropdownMenu.Item>
								{/if}
								{#if inst.enabled}
									<DropdownMenu.Item onSelect={() => ondisable(inst)}>Disable</DropdownMenu.Item>
								{:else}
									<DropdownMenu.Item onSelect={() => onenable(inst)}>Enable</DropdownMenu.Item>
								{/if}
								<DropdownMenu.Separator />
								<DropdownMenu.Item variant="destructive" onSelect={() => ondelete(inst)}>Delete</DropdownMenu.Item>
							</DropdownMenu.Content>
						</DropdownMenu.Root>
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
