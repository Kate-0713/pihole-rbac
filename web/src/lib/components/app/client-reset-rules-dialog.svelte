<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import TrashIcon from '@lucide/svelte/icons/trash-2';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import {
		emptyRow,
		matchLabel,
		rulesProblem,
		scopeKey,
		toRuleRows,
		toRulesInput,
		type Match,
		type RuleRow,
		type Rules
	} from '#lib/clientreset.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Edits every rule at once, as the API replaces them all. A row is one rule: where it applies, the comment prefix it
	// matches, and the Pi-hole groups (exact names or name prefixes, separated by commas) its clients go back to. The
	// groups aren't checked against the Pi-holes here; the page's preview, and each run, say if one is missing.
	let {
		open = $bindable(false),
		settings,
		onsaved
	}: { open: boolean; settings: Rules; onsaved: () => Promise<void> | void } = $props();

	let rows = $state<RuleRow[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Each time the dialog opens it starts again from the saved rules. Built in a local first: reading `rows` after
	// setting it would make the effect depend on it, and run again every time it does.
	$effect(() => {
		if (!open) return;
		const fresh = toRuleRows(settings.rules);
		rows = fresh.length > 0 ? fresh : [emptyRow()];
		error = null;
	});

	let choices = $derived([
		...settings.instances.map((i) => ({ value: scopeKey('instance', i.id), label: i.name, kind: 'Instance' })),
		...settings.groups.map((g) => ({ value: scopeKey('group', g.id), label: g.name, kind: 'Mirrored group' }))
	]);
	const labelOf = (value: string) => {
		const c = choices.find((x) => x.value === value);
		return c ? `${c.label} (${c.kind.toLowerCase()})` : 'Choose…';
	};
	let problem = $derived(rulesProblem(rows));

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (problem) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.PUT('/api/v1/client-reset/rules', { body: toRulesInput(rows) }));
			notices.success('Client reset rules saved.');
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
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-3xl">
		<Dialog.Header>
			<Dialog.Title>Client reset rules</Dialog.Title>
			<Dialog.Description>
				Clients whose comment starts with a rule's prefix (case-sensitive) are put back in exactly its Pi-hole groups.
				When two prefixes match, the longer one wins.
			</Dialog.Description>
		</Dialog.Header>

		<form id="client-reset-rules-form" class="grid gap-3" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			{#each rows as row, i (i)}
				<fieldset class="grid gap-2 rounded-md border p-3 sm:grid-cols-2" aria-label="Rule {i + 1}">
					<div class="grid gap-1">
						<span id="reset-scope-{i}" class="text-muted-foreground text-xs">Instance or mirrored group</span>
						<Select.Root type="single" bind:value={row.scope}>
							<Select.Trigger class="w-full" aria-labelledby="reset-scope-{i}">{labelOf(row.scope)}</Select.Trigger>
							<Select.Content>
								{#each choices as c (c.value)}
									<Select.Item value={c.value} label={c.label}>{c.label} <span class="text-muted-foreground text-xs">{c.kind}</span></Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</div>
					<div class="grid gap-1">
						<Label for="reset-prefix-{i}" class="text-muted-foreground text-xs font-normal">Comment starts with</Label>
						<Input id="reset-prefix-{i}" bind:value={row.prefix} autocomplete="off" placeholder="TEST-" class="font-mono" />
					</div>
					<div class="grid gap-1">
						<span id="reset-match-{i}" class="text-muted-foreground text-xs">Pi-hole groups are</span>
						<!-- A function binding: bits-ui's Select holds a string, and the getter and setter convert at its edge. -->
						<Select.Root type="single" bind:value={() => row.match, (v) => (row.match = v as Match)}>
							<Select.Trigger class="w-full" aria-labelledby="reset-match-{i}">{matchLabel[row.match]}</Select.Trigger>
							<Select.Content>
								<Select.Item value="names" label={matchLabel.names}>{matchLabel.names}</Select.Item>
								<Select.Item value="prefixes" label={matchLabel.prefixes}>{matchLabel.prefixes}</Select.Item>
							</Select.Content>
						</Select.Root>
					</div>
					<div class="grid gap-1">
						<Label for="reset-groups-{i}" class="text-muted-foreground text-xs font-normal">
							{row.match === 'names' ? 'Pi-hole groups' : 'Pi-hole group prefixes'}, separated by commas
						</Label>
						<div class="flex gap-1">
							<Input
								id="reset-groups-{i}"
								bind:value={row.groups}
								autocomplete="off"
								placeholder={row.match === 'names' ? 'AUTOSET-lab, AUTOSET-staff' : 'AUTOSET-'}
							/>
							<Button variant="ghost" size="icon" aria-label="Remove rule {i + 1}" onclick={() => (rows = rows.filter((_, j) => j !== i))}>
								<TrashIcon />
							</Button>
						</div>
					</div>
				</fieldset>
			{/each}
			<Button variant="outline" size="sm" class="w-fit" onclick={() => (rows = [...rows, emptyRow()])}>
				<PlusIcon /> Add a rule
			</Button>
			{#if problem}
				<p class="text-destructive text-sm">{problem}</p>
			{/if}
			<p class="text-muted-foreground text-xs">
				Exact names must all exist on every instance a rule runs on, or it changes nothing there. Name prefixes take
				every group whose name starts with one of them.
			</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="client-reset-rules-form" disabled={busy || problem !== null}>{busy ? 'Saving…' : 'Save'}</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
