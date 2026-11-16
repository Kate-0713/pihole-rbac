<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { untrack } from 'svelte';
	import { api, unwrap, type Schemas } from '#lib/api/client.js';
	import { browserZone } from '#lib/clientreset.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { groupNames, type PiholeGroup } from '#lib/pihole.js';
	import { blankForm, formProblem, maxReasonChars, presetsWithin, startBody, type Form, type Limits } from '#lib/temp-changes.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';
	import GroupPicker from './group-picker.svelte';

	type PiholeClient = Schemas['PiholeClient'];

	// Moves a client to other Pi-hole groups for a set time, and the app puts it back. The dialog only asks; the server
	// checks the same rules again (see temp-changes.ts for the browser's copy of them).
	let {
		open = $bindable(false),
		target,
		targetName,
		groups,
		client,
		limits,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		groups: PiholeGroup[];
		client: PiholeClient | null;
		limits: Limits;
		onsaved: () => Promise<void> | void;
	} = $props();

	const zone = browserZone();
	let form = $state<Form>(blankForm([], 60));
	// The time the form's checks are made against. It is set when the dialog opens and again when it is submitted:
	// a clock that ticked inside $derived would re-run the checks every second for nothing.
	let now = $state(new Date());
	let error = $state<string | null>(null);
	let busy = $state(false);

	// Svelte convention: an $effect re-runs when anything it reads changes. This one must run when the dialog opens
	// and not when the page reloads `limits` (it does, every 30 seconds), or the form would be wiped as you type.
	// `untrack` reads a value without subscribing to it.
	$effect(() => {
		if (!open || !client) return;
		const current = client.groups;
		untrack(() => {
			form = blankForm(current, limits.max_minutes);
			now = new Date();
			error = null;
		});
	});

	let presets = $derived(presetsWithin(limits.max_minutes));
	let problem = $derived(client ? formProblem(form, client.groups, limits, now, zone) : null);
	let returnsTo = $derived(client ? groupNames(client.groups, groups).join(', ') || 'no groups' : '');

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!client) return;
		now = new Date();
		if (formProblem(form, client.groups, limits, now, zone)) return;
		busy = true;
		error = null;
		try {
			const { results, change } = await unwrap(
				api.POST('/api/v1/targets/{target}/clients/temporary', {
					params: { path: { target } },
					body: startBody(client.client, form, groups, now, zone)
				})
			);
			const until = change ? ` until ${formatDateTime(change.ends_at)}` : '';
			reportResults(results, { done: `${client.client}'s groups changed${until}`, failed: `Couldn't change ${client.client}` });
			open = false;
			await onsaved();
		} catch (e) {
			error = failureMessage(e);
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="top-[5vh] max-h-[90vh] translate-y-0 overflow-y-auto sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>Change groups temporarily</Dialog.Title>
			<Dialog.Description>
				{#if client}
					<span class="font-mono break-all">{client.client}</span>{#if client.name}&nbsp;({client.name}){/if} on {targetName}.
					The app puts it back when the time is up.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="temp-change-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}

			<GroupPicker {groups} bind:selected={form.groups} idPrefix="temp" disabled={busy} />
			<p class="text-muted-foreground -mt-2 text-xs">
				The client returns to: {returnsTo}. Changes someone else makes to it meanwhile are kept.
			</p>

			<fieldset class="grid gap-2" disabled={busy}>
				<legend class="mb-1 text-sm font-medium">For how long</legend>
				<div class="flex flex-wrap gap-2" role="group" aria-label="For how long">
					{#each presets as p (p.minutes)}
						<Button
							type="button"
							size="sm"
							variant={form.mode === 'preset' && form.minutes === p.minutes ? 'default' : 'outline'}
							aria-pressed={form.mode === 'preset' && form.minutes === p.minutes}
							onclick={() => {
								form.mode = 'preset';
								form.minutes = p.minutes;
							}}
						>
							{p.label}
						</Button>
					{/each}
					<Button
						type="button"
						size="sm"
						variant={form.mode === 'until' ? 'default' : 'outline'}
						aria-pressed={form.mode === 'until'}
						onclick={() => (form.mode = 'until')}
					>
						Until…
					</Button>
				</div>
				{#if form.mode === 'until'}
					<div class="flex flex-wrap items-center gap-2">
						<Input type="date" class="w-40" bind:value={form.untilDate} aria-label="End date" />
						<Input type="time" class="w-32" bind:value={form.untilTime} aria-label="End time" />
						<span class="text-muted-foreground text-xs">{zone}</span>
					</div>
				{/if}
			</fieldset>

			<div class="grid gap-2">
				<Label for="temp-reason">
					Reason
					{#if !limits.reason_required}<span class="text-muted-foreground font-normal">(optional)</span>{/if}
				</Label>
				<Input
					id="temp-reason"
					bind:value={form.reason}
					maxlength={maxReasonChars}
					autocomplete="off"
					placeholder="Kept with the change and in the audit log"
					disabled={busy}
				/>
			</div>

			<p class="text-muted-foreground min-h-5 text-sm" aria-live="polite">{problem?.message ?? ''}</p>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="temp-change-form" disabled={busy || problem !== null}>
				{busy ? 'Changing…' : 'Change groups'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
