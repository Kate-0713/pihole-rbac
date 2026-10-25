<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import TrashIcon from '@lucide/svelte/icons/trash-2';
	import PlusIcon from '@lucide/svelte/icons/plus';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		removedNames,
		rowsProblem,
		scopeKey,
		toProtectedInput,
		toRows,
		type ProtectedRow,
		type ProtectedSettings
	} from '#lib/notifications.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Edits every protected group at once: a row per instance or mirrored group, with its Pi-hole group names separated
	// by commas. The names aren't checked against the Pi-holes (doing so would need a permission on each instance), so
	// they are matched as typed, ignoring case.
	let {
		open = $bindable(false),
		settings,
		onsaved
	}: { open: boolean; settings: ProtectedSettings; onsaved: () => Promise<void> | void } = $props();

	let rows = $state<ProtectedRow[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Built in a local first: reading `rows` after setting it would make the effect depend on it, and run again
	// every time it does.
	$effect(() => {
		if (!open) return;
		const fresh = toRows(settings);
		rows = fresh.length > 0 ? fresh : [{ scope: '', names: '' }];
		error = null;
	});

	// What a row can name, labelled for the select.
	let choices = $derived([
		...settings.instances.map((i) => ({ value: scopeKey('instance', i.id), label: i.name, kind: 'Instance' })),
		...settings.groups.map((g) => ({ value: scopeKey('group', g.id), label: g.name, kind: 'Mirrored group' }))
	]);
	const labelOf = (value: string) => {
		const c = choices.find((x) => x.value === value);
		return c ? `${c.label} (${c.kind.toLowerCase()})` : 'Choose…';
	};
	let problem = $derived(rowsProblem(rows));
	let removed = $derived(removedNames(settings, rows));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (problem) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.PUT('/api/v1/notifications/protected-groups', { body: toProtectedInput(rows) }));
			notices.success('Protected groups saved.');
			open = false;
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
		<Dialog.Header>
			<Dialog.Title>Protected groups</Dialog.Title>
			<Dialog.Description>
				A client added to one of these Pi-hole groups raises the protected_group_add alert. An instance's own groups
				and its mirrored group's both apply to it.
			</Dialog.Description>
		</Dialog.Header>

		<form id="protected-form" class="grid gap-3" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			{#each rows as row, i (i)}
				<div class="grid gap-2 rounded-md border p-3 sm:grid-cols-[14rem_1fr_auto] sm:items-end">
					<div class="grid gap-1">
						<span id="protected-scope-{i}" class="text-muted-foreground text-xs">Instance or group</span>
						<Select.Root type="single" bind:value={row.scope}>
							<Select.Trigger class="w-full" aria-labelledby="protected-scope-{i}">{labelOf(row.scope)}</Select.Trigger>
							<Select.Content>
								{#each choices as c (c.value)}
									<Select.Item value={c.value} label={c.label}>{c.label} <span class="text-muted-foreground text-xs">{c.kind}</span></Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</div>
					<div class="grid gap-1">
						<Label for="protected-names-{i}" class="text-muted-foreground text-xs font-normal">Pi-hole groups, separated by commas</Label>
						<Input id="protected-names-{i}" bind:value={row.names} autocomplete="off" placeholder="kids, guests" />
					</div>
					<Button
						variant="ghost"
						size="icon"
						aria-label="Remove row {i + 1}"
						onclick={() => (rows = rows.filter((_, j) => j !== i))}
					>
						<TrashIcon />
					</Button>
				</div>
			{/each}
			<Button variant="outline" size="sm" class="w-fit" onclick={() => (rows = [...rows, { scope: '', names: '' }])}>
				<PlusIcon /> Add a row
			</Button>
			{#if problem}
				<p class="text-destructive text-sm">{problem}</p>
			{/if}
			{#if removed.length > 0}
				<Alert>
					<AlertDescription>
						Saving tells the channels that receive protected_group_add that these alerts stop: {removed.join(', ')}.
					</AlertDescription>
				</Alert>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="protected-form" disabled={busy || problem !== null}>{busy ? 'Saving…' : 'Save'}</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
