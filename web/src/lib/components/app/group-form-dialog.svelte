<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		emptyForm,
		formChanged,
		formFrom,
		groupProblems,
		mirroredElsewhere,
		modeDescription,
		modeLabel,
		toInput,
		type Group,
		type GroupForm,
		type GroupMode
	} from '#lib/groups.js';
	import type { Instance } from '#lib/instances.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// One dialog for adding a group and for changing one. A save replaces the whole group (name, mode, members and
	// primary), as the API does.
	let {
		open = $bindable(false),
		group = null,
		groups,
		instances,
		onsaved
	}: {
		open: boolean;
		group?: Group | null;
		// Every group, so the form can see names already taken and instances already in a mirrored group.
		groups: Group[];
		instances: Instance[];
		onsaved: () => Promise<void> | void;
	} = $props();

	let form = $state<GroupForm>(emptyForm());
	let before = $state<GroupForm>(emptyForm());
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	// Reset the form each time the dialog opens. An $effect re-runs when what it reads changes, here `open` and
	// `group`.
	$effect(() => {
		if (!open) return;
		form = group ? formFrom(group) : emptyForm();
		before = group ? formFrom(group) : emptyForm();
		error = null;
		touched = false;
	});

	let self = $derived(group?.id ?? null);
	let elsewhere = $derived(mirroredElsewhere(groups, self));
	let sortedInstances = $derived([...instances].sort((a, b) => a.name.localeCompare(b.name)));
	let problems = $derived(groupProblems(form, groups, self));
	let ready = $derived(Object.values(problems).every((p) => p === null));
	let chosen = $derived(sortedInstances.filter((i) => form.members.includes(i.id)));
	let primaryName = $derived(chosen.find((i) => i.id === form.primary)?.name);
	let becomingIndependent = $derived(group?.mode === 'mirrored' && form.mode === 'independent');

	// bits-ui's single Select works with string values. The bindings below are Svelte 5 function bindings
	// (`bind:value={getter, setter}`), which convert at the Select's edge without a second piece of state.
	const getMode = () => form.mode;
	function setMode(v: string) {
		form.mode = v as GroupMode;
		if (form.mode === 'mirrored' && form.primary === 0 && form.members.length === 1) form.primary = form.members[0];
	}
	const getPrimary = () => (form.primary === 0 ? '' : String(form.primary));
	const setPrimary = (v: string) => (form.primary = v === '' ? 0 : Number(v));

	function toggle(id: number, on: boolean) {
		form.members = on ? [...form.members, id] : form.members.filter((x) => x !== id);
		// A primary that leaves the members stops being the primary; a sole member of a mirrored group becomes it.
		if (!form.members.includes(form.primary)) form.primary = 0;
		if (form.mode === 'mirrored' && form.primary === 0 && form.members.length === 1) form.primary = form.members[0];
		touched = true;
	}

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		if (group && !formChanged(before, form)) {
			open = false;
			return;
		}
		busy = true;
		error = null;
		const body = toInput(form);
		try {
			if (group) {
				const saved = await unwrap(
					api.PUT('/api/v1/instance-groups/{id}', { params: { path: { id: group.id } }, body })
				);
				notices.success(`${saved.name} saved.`);
			} else {
				const saved = await unwrap(api.POST('/api/v1/instance-groups', { body }));
				notices.success(`${saved.name} added.`);
			}
			open = false;
			await onsaved();
		} catch (e) {
			// Shown in the dialog, which stays open, so the group can be fixed and saved again.
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{group ? `Edit ${group.name}` : 'Add a group'}</Dialog.Title>
			<Dialog.Description>Instance groups organise instances and scope permissions.</Dialog.Description>
		</Dialog.Header>

		<form id="group-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="group-name">Name</Label>
				<Input
					id="group-name"
					bind:value={form.name}
					autocomplete="off"
					placeholder="Site A"
					aria-invalid={touched && problems.name !== null}
					aria-describedby="group-name-hint"
				/>
				{#if touched && problems.name}
					<p id="group-name-hint" class="text-destructive text-sm">{problems.name}</p>
				{/if}
			</div>

			<div class="grid gap-2">
				<Label for="group-mode">Mode</Label>
				<Select.Root type="single" bind:value={getMode, setMode}>
					<Select.Trigger id="group-mode" class="w-full" aria-describedby="group-mode-hint">
						{modeLabel[form.mode]}
					</Select.Trigger>
					<Select.Content>
						<Select.Item value="independent" label={modeLabel.independent}>{modeLabel.independent}</Select.Item>
						<Select.Item value="mirrored" label={modeLabel.mirrored}>{modeLabel.mirrored}</Select.Item>
					</Select.Content>
				</Select.Root>
				<p id="group-mode-hint" class="text-muted-foreground text-sm">{modeDescription[form.mode]}</p>
				{#if becomingIndependent}
					<p class="text-muted-foreground text-sm">
						A mirrored group can't become independent while a role holds drift permissions on it. Remove those
						first on the roles page.
					</p>
				{/if}
			</div>

			<fieldset class="grid gap-2" aria-describedby="group-members-hint">
				<legend class="mb-2 text-sm font-medium">Members</legend>
				{#if sortedInstances.length === 0}
					<p class="text-muted-foreground text-sm">There are no instances yet.</p>
				{/if}
				{#each sortedInstances as inst (inst.id)}
					<!-- In mirrored mode, an instance already in another mirrored group can't be ticked; one already ticked
					     (from before the mode changed) stays unlockable so it can be removed. -->
					{@const other = form.mode === 'mirrored' ? elsewhere.get(inst.id) : undefined}
					{@const ticked = form.members.includes(inst.id)}
					<div class="flex items-start gap-2">
						<Checkbox
							id="member-{inst.id}"
							class="mt-0.5"
							checked={ticked}
							disabled={other !== undefined && !ticked}
							onCheckedChange={(on) => toggle(inst.id, on === true)}
							aria-describedby={other || !inst.enabled ? `member-${inst.id}-note` : undefined}
						/>
						<div class="grid gap-0.5">
							<Label for="member-{inst.id}" class="font-normal">{inst.name}</Label>
							{#if other || !inst.enabled}
								<p id="member-{inst.id}-note" class="text-muted-foreground text-xs">
									{[other ? `In the mirrored group "${other}"` : '', inst.enabled ? '' : 'Disabled'].filter(Boolean).join(' · ')}
								</p>
							{/if}
						</div>
					</div>
				{/each}
				{#if touched && problems.members}
					<p id="group-members-hint" class="text-destructive text-sm">{problems.members}</p>
				{/if}
			</fieldset>

			{#if form.mode === 'mirrored'}
				<div class="grid gap-2">
					<Label for="group-primary">Primary</Label>
					<Select.Root type="single" bind:value={getPrimary, setPrimary} disabled={chosen.length === 0}>
						<Select.Trigger
							id="group-primary"
							class="w-full"
							aria-invalid={touched && problems.primary !== null}
							aria-describedby="group-primary-hint"
						>
							{primaryName ?? 'Choose the primary'}
						</Select.Trigger>
						<Select.Content>
							{#each chosen as inst (inst.id)}
								<Select.Item value={String(inst.id)} label={inst.name}>{inst.name}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
					{#if touched && problems.primary}
						<p id="group-primary-hint" class="text-destructive text-sm">{problems.primary}</p>
					{:else}
						<p id="group-primary-hint" class="text-muted-foreground text-sm">
							The source of truth: reads come from it, and the other members are compared with it for drift.
						</p>
					{/if}
				</div>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="group-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if group}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
