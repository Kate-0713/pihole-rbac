<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { browserZone, timeZones } from '#lib/clientreset.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import {
		blankForm,
		days,
		formLength,
		formOf,
		formProblem,
		inputOf,
		kindLabel,
		lengthText,
		maxMinutes,
		suggestEndDays,
		type Form,
		type Schedule,
		type ScheduleKind
	} from '#lib/schedules.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// One dialog for adding a schedule and for changing one. The rules the server checks are checked as you type
	// (formProblem); whether the Pi-hole group exists, and overlaps with other schedules, come back from the server and
	// show here. A change is sent whole, as a PATCH of every field but the kind, which can't change.
	let {
		open = $bindable(false),
		target,
		targetName,
		schedule = null,
		groups,
		groupMax,
		canBlocking,
		canGroups,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		schedule?: Schedule | null;
		// The target's Pi-hole group names, for the picker; Default is left out, as it can't be scheduled.
		groups: string[];
		// The longest a group window can be now, in minutes.
		groupMax: number;
		// blocking.toggle and piholegroups.edit on the target: the kinds this user can schedule.
		canBlocking: boolean;
		canGroups: boolean;
		onsaved: () => Promise<void> | void;
	} = $props();

	const zones = timeZones();
	let form = $state<Form>(blankForm(browserZone()));
	let touched = $state(false);
	let busy = $state(false);
	let error = $state<string | null>(null);
	// endDays follows the times until someone chooses it, so 21:00 to 07:00 means the next day without asking.
	let endDaysChosen = $state(false);

	// Filled each time the dialog opens; it reads only open and schedule, so typing doesn't reset the fields.
	$effect(() => {
		if (!open) return;
		const zone = browserZone();
		form = schedule ? formOf(schedule, zone) : { ...blankForm(zone), kind: canBlocking ? 'blocking_off' : 'group_enabled' };
		touched = false;
		error = null;
		endDaysChosen = !!schedule;
	});
	$effect(() => {
		if (!endDaysChosen && form.repeat === 'weekly') form.endDays = suggestEndDays(form.start, form.end);
	});

	let kinds = $derived(
		(['blocking_off', 'group_enabled', 'group_disabled'] as ScheduleKind[]).filter((k) =>
			k === 'blocking_off' ? canBlocking : canGroups
		)
	);
	let isGroup = $derived(form.kind !== 'blocking_off');
	let problem = $derived(formProblem(form, groupMax, new Date()));
	let length = $derived(formLength(form));
	let max = $derived(maxMinutes(form, groupMax));
	// A group that has gone from Pi-hole since the schedule was saved stays in the picker, so it can be seen.
	let groupChoices = $derived(
		[...groups, ...(form.group && !groups.includes(form.group) ? [form.group] : [])].filter((g) => g !== 'Default')
	);
	let hint = (field: string) => (touched && problem?.field === field ? problem.message : null);

	const kindText: Record<ScheduleKind, string> = {
		blocking_off: 'Turn blocking off during the window. Pi-hole turns it back on by itself at the end.',
		group_enabled: 'Enable a Pi-hole group during the window, and disable it at the end.',
		group_disabled: 'Disable a Pi-hole group during the window, and enable it again at the end.'
	};

	function toggleDay(bit: number, on: boolean) {
		form.days = on ? form.days | bit : form.days & ~bit;
	}

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (problem) return;
		busy = true;
		error = null;
		const body = inputOf(form);
		try {
			if (schedule) {
				const { kind: _kind, ...change } = body;
				await unwrap(
					api.PATCH('/api/v1/targets/{target}/schedules/{id}', {
						params: { path: { target, id: schedule.id } },
						body: change
					})
				);
				notices.success(`Schedule ${form.name} saved.`);
			} else {
				await unwrap(api.POST('/api/v1/targets/{target}/schedules', { params: { path: { target } }, body }));
				notices.success(`Schedule ${form.name} added.`);
			}
			open = false;
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<!-- Pinned near the top rather than centred: the form grows and shrinks as hints come and go, and a centred dialog
	would move every field, a date picker included, each time. -->
<Dialog.Root bind:open>
	<Dialog.Content class="top-[5vh] max-h-[90vh] translate-y-0 overflow-y-auto sm:max-w-xl">
		<Dialog.Header>
			<Dialog.Title>{schedule ? 'Change schedule' : 'Add a schedule'}</Dialog.Title>
			<Dialog.Description>
				On {targetName}. A schedule acts from its next start or end: saving doesn't change anything now, even during a
				window.
			</Dialog.Description>
		</Dialog.Header>

		<form id="schedule-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="schedule-name">Name</Label>
				<Input id="schedule-name" bind:value={form.name} maxlength={100} autocomplete="off" placeholder="Lab mornings" />
				{#if hint('name')}<p class="text-destructive text-sm">{hint('name')}</p>{/if}
			</div>

			<div class="grid gap-2">
				<Label for="schedule-kind">What it does</Label>
				{#if schedule}
					<p id="schedule-kind" class="text-sm">{kindLabel[form.kind]}</p>
				{:else}
					<Select.Root type="single" bind:value={form.kind}>
						<Select.Trigger id="schedule-kind" class="w-full">{kindLabel[form.kind]}</Select.Trigger>
						<Select.Content>
							{#each kinds as k (k)}
								<Select.Item value={k} label={kindLabel[k]}>{kindLabel[k]}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
				{/if}
				<p class="text-muted-foreground text-xs">{kindText[form.kind]}</p>
			</div>

			{#if isGroup}
				<div class="grid gap-2">
					<Label for="schedule-group">Pi-hole group</Label>
					<Select.Root type="single" bind:value={form.group}>
						<Select.Trigger id="schedule-group" class="w-full">{form.group || 'Choose a group'}</Select.Trigger>
						<Select.Content>
							{#each groupChoices as g (g)}
								<Select.Item value={g} label={g}>{g}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
					{#if hint('pihole_group')}
						<p class="text-destructive text-sm">{hint('pihole_group')}</p>
					{:else}
						<p class="text-muted-foreground text-xs">
							Switching a group changes filtering for every client in it. The Default group can't be scheduled.
						</p>
					{/if}
				</div>
			{/if}

			<fieldset class="grid gap-2">
				<legend class="mb-1 text-sm font-medium">Repeats</legend>
				<div class="flex gap-4 text-sm">
					<label class="flex items-center gap-2">
						<input type="radio" name="schedule-repeat" value="weekly" bind:group={form.repeat} /> Every week
					</label>
					<label class="flex items-center gap-2">
						<input type="radio" name="schedule-repeat" value="once" bind:group={form.repeat} /> Once
					</label>
				</div>
			</fieldset>

			{#if form.repeat === 'weekly'}
				<fieldset class="grid gap-2">
					<legend class="mb-1 text-sm font-medium">Starts on</legend>
					<div class="flex flex-wrap gap-3">
						{#each days as d (d.bit)}
							<label class="flex items-center gap-1.5 text-sm">
								<Checkbox
									checked={(form.days & d.bit) !== 0}
									onCheckedChange={(on) => toggleDay(d.bit, on === true)}
									aria-label={d.long}
								/>
								{d.short}
							</label>
						{/each}
					</div>
					{#if hint('days')}<p class="text-destructive text-sm">{hint('days')}</p>{/if}
				</fieldset>
				<div class="grid items-start gap-4 sm:grid-cols-3">
					<div class="grid gap-2">
						<Label for="schedule-start">From</Label>
						<Input id="schedule-start" type="time" bind:value={form.start} required />
					</div>
					<div class="grid gap-2">
						<Label for="schedule-end">To</Label>
						<Input id="schedule-end" type="time" bind:value={form.end} required />
					</div>
					<div class="grid gap-2">
						<Label for="schedule-end-days">Ends</Label>
						<select
							id="schedule-end-days"
							class="border-input bg-background h-9 rounded-md border px-2 text-sm"
							value={String(form.endDays)}
							onchange={(e) => {
								form.endDays = Number(e.currentTarget.value);
								endDaysChosen = true;
							}}
						>
							<option value="0">The same day</option>
							<option value="1">The next day</option>
							{#each [2, 3, 4, 5, 6, 7] as n (n)}<option value={String(n)}>{n} days later</option>{/each}
						</select>
					</div>
				</div>
				{#each ['start', 'end', 'end_days'] as f (f)}
					{#if hint(f)}<p class="text-destructive text-sm">{hint(f)}</p>{/if}
				{/each}
			{:else}
				<div class="grid items-start gap-4 sm:grid-cols-2">
					<div class="grid gap-2">
						<Label for="schedule-start-date">Starts</Label>
						<div class="flex gap-2">
							<Input id="schedule-start-date" type="date" bind:value={form.startDate} aria-label="Start date" />
							<Input id="schedule-start-time" type="time" bind:value={form.startTime} aria-label="Start time" />
						</div>
						{#if hint('starts_at')}<p class="text-destructive text-sm">{hint('starts_at')}</p>{/if}
					</div>
					<div class="grid gap-2">
						<Label for="schedule-end-date">Ends</Label>
						<div class="flex gap-2">
							<Input id="schedule-end-date" type="date" bind:value={form.endDate} aria-label="End date" />
							<Input id="schedule-end-time" type="time" bind:value={form.endTime} aria-label="End time" />
						</div>
						{#if hint('ends_at')}<p class="text-destructive text-sm">{hint('ends_at')}</p>{/if}
					</div>
				</div>
			{/if}

			<div class="grid gap-2">
				<Label for="schedule-zone">Time zone</Label>
				<Input id="schedule-zone" list="schedule-zones" bind:value={form.zone} autocomplete="off" spellcheck={false} />
				<datalist id="schedule-zones">
					{#each zones as z (z)}<option value={z}></option>{/each}
				</datalist>
				{#if hint('time_zone')}<p class="text-destructive text-sm">{hint('time_zone')}</p>{/if}
			</div>

			<p class="text-muted-foreground text-sm" aria-live="polite">
				{#if Number.isFinite(length) && length > 0}
					{lengthText(length)} long, of at most {lengthText(max)}.
				{:else}
					At most {lengthText(max)} long.
				{/if}
				{#if form.repeat === 'weekly'}A window across a daylight saving change is an hour longer or shorter.{/if}
			</p>

			<div class="flex items-center gap-2">
				<Checkbox id="schedule-enabled" bind:checked={form.enabled} />
				<Label for="schedule-enabled">On</Label>
			</div>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="schedule-form" disabled={busy || (touched && problem !== null)}>
				{#if busy}Saving…{:else if schedule}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
