<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { groupCheckLabel, type GroupCheck, type Mapping } from '#lib/ldap.js';
	import { needsConfirmation, type Role } from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Which LDAP groups give which roles. Adding a mapping looks the group up afterwards and warns if the directory
	// doesn't have it; each mapping can be checked again on demand. Nothing about the check is stored.
	let {
		mappings,
		roles,
		onchanged
	}: { mappings: Mapping[]; roles: Role[]; onchanged: () => Promise<void> | void } = $props();

	let roleByID = $derived(new Map(roles.map((r) => [r.id, r])));
	let rows = $derived(
		[...mappings].sort(
			(a, b) =>
				(roleByID.get(a.role_id)?.name ?? '').localeCompare(roleByID.get(b.role_id)?.name ?? '') ||
				a.group_dn.localeCompare(b.group_dn)
		)
	);
	// Roles the caller holds every grant of: the only ones they can map or unmap.
	let mappable = $derived(roles.filter((r) => r.manageable).sort((a, b) => a.name.localeCompare(b.name)));

	let groupDN = $state('');
	let roleID = $state('');
	let adding = $state(false);
	let addError = $state<string | null>(null);

	// Results of "Check", by mapping ID, for as long as the page is open.
	let checks = $state<Record<number, { result?: GroupCheck; error?: string; busy?: boolean }>>({});

	let removing = $state<Mapping | null>(null);
	let removeOpen = $state(false);
	let removeError = $state<string | null>(null);
	let removeConfirm = $state<string | null>(null);
	let removeBusy = $state(false);

	async function add(event: SubmitEvent) {
		event.preventDefault();
		const role = roleByID.get(Number(roleID));
		if (!role || groupDN.trim() === '') {
			addError = 'Enter a group DN and choose a role.';
			return;
		}
		adding = true;
		addError = null;
		try {
			const res = await unwrap(
				api.POST('/api/v1/roles/{id}/ldap-groups', { params: { path: { id: role.id } }, body: { group_dn: groupDN.trim() } })
			);
			checks[res.mapping.id] = res.check ? { result: res.check } : { error: res.check_error };
			if (res.check && !res.check.exists) {
				notices.error(`Mapped to ${role.name}, but the directory has no such group. Check the DN.`);
			} else {
				notices.success(`Group mapped to ${role.name}.`);
			}
			groupDN = '';
			await onchanged();
		} catch (e) {
			addError = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			adding = false;
		}
	}

	async function check(m: Mapping) {
		checks[m.id] = { busy: true };
		try {
			const result = await unwrap(api.POST('/api/v1/ldap/check-group', { body: { group_dn: m.group_dn } }));
			checks[m.id] = { result };
		} catch (e) {
			checks[m.id] = { error: e instanceof ApiError ? e.message : 'The check failed.' };
		}
	}

	function askRemove(m: Mapping) {
		removing = m;
		removeError = null;
		removeConfirm = null;
		removeOpen = true;
	}

	async function remove(event: MouseEvent) {
		event.preventDefault();
		if (!removing) return;
		removeBusy = true;
		removeError = null;
		try {
			await unwrap(
				api.DELETE('/api/v1/roles/{id}/ldap-groups/{mapping_id}', {
					params: {
						path: { id: removing.role_id, mapping_id: removing.id },
						query: removeConfirm !== null ? { confirm: true } : {}
					}
				})
			);
			notices.success('Mapping removed. Members lose the role within a minute, unless another group gives it.');
			removeOpen = false;
			await onchanged();
		} catch (e) {
			if (needsConfirmation(e)) removeConfirm = e.message;
			else removeError = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			removeBusy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Group mappings</h2></Card.Title>
		<Card.Description>
			Members of a mapped group get its role when they log in, and within a minute of a change while logged in.
		</Card.Description>
	</Card.Header>
	<Card.Content class="grid gap-4">
		{#if rows.length === 0}
			<p class="text-muted-foreground text-sm">No groups are mapped yet, so no LDAP user can log in.</p>
		{:else}
			<!-- A list rather than a table: DNs are long, and the card is half the page wide, so each mapping wraps onto
			     its own lines instead of pushing its buttons out of view. -->
			<ul class="divide-y rounded-md border">
				{#each rows as m (m.id)}
					{@const role = roleByID.get(m.role_id)}
					{@const c = checks[m.id]}
					<li class="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 p-3">
						<div class="grid min-w-0 gap-1">
							<p class="font-mono text-xs break-all">{m.group_dn}</p>
							<p class="text-sm">
								<span class="text-muted-foreground">Role:</span>
								{role?.name ?? `role ${m.role_id}`}
							</p>
							<p class="text-sm">
								{#if c?.busy}
									<span class="text-muted-foreground">Checking…</span>
								{:else if c?.result}
									<span class={c.result.exists ? '' : 'text-destructive'}>{groupCheckLabel(c.result)}</span>
								{:else if c?.error}
									<span class="text-destructive">{c.error}</span>
								{/if}
							</p>
						</div>
						<div class="flex gap-1">
							<Button variant="outline" size="sm" onclick={() => check(m)} disabled={c?.busy}>Check</Button>
							{#if role?.manageable}
								<Button variant="ghost" size="sm" onclick={() => askRemove(m)} aria-label="Remove {m.group_dn} from {role.name}">
									Remove
								</Button>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		{/if}

		<form class="grid gap-3 sm:grid-cols-[1fr_12rem_auto] sm:items-end" onsubmit={add}>
			<div class="grid gap-2">
				<Label for="mapping-dn">Group DN</Label>
				<Input
					id="mapping-dn"
					bind:value={groupDN}
					placeholder="cn=pihole-staff,ou=groups,dc=example,dc=com"
					autocomplete="off"
					spellcheck={false}
					class="font-mono"
				/>
			</div>
			<div class="grid gap-2">
				<Label for="mapping-role">Role</Label>
				<Select.Root type="single" bind:value={roleID}>
					<Select.Trigger id="mapping-role" class="w-full">
						{roleByID.get(Number(roleID))?.name ?? 'Choose a role'}
					</Select.Trigger>
					<Select.Content>
						{#each mappable as r (r.id)}
							<Select.Item value={String(r.id)} label={r.name}>{r.name}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
			<Button type="submit" disabled={adding}>{adding ? 'Adding…' : 'Add mapping'}</Button>
		</form>
		{#if addError}
			<Alert variant="destructive">
				<AlertDescription>{addError}</AlertDescription>
			</Alert>
		{/if}
		<p class="text-muted-foreground text-xs">Only roles whose permissions you all hold can be mapped or unmapped.</p>
	</Card.Content>
</Card.Root>

<AlertDialog.Root bind:open={removeOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Remove this mapping?</AlertDialog.Title>
			<AlertDialog.Description>
				Members of <span class="font-mono break-all">{removing?.group_dn}</span> stop getting
				{roleByID.get(removing?.role_id ?? 0)?.name ?? 'the role'} within a minute, unless another of their groups
				gives it.
			</AlertDialog.Description>
		</AlertDialog.Header>
		{#if removeConfirm}
			<Alert variant="destructive"><AlertDescription>{removeConfirm}</AlertDescription></Alert>
		{/if}
		{#if removeError}
			<Alert variant="destructive"><AlertDescription>{removeError}</AlertDescription></Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={removeBusy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={removeBusy} onclick={remove}>
				{#if removeBusy}Removing…{:else if removeConfirm}Remove anyway{:else}Remove{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
