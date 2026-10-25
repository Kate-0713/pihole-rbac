<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { describeRetention, retentionProblem, retentionRange } from '#lib/audit.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import type { GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// How long audit entries are kept. It's one of the general settings, which are saved together, so the save sends
	// the session settings as they were loaded alongside the new retention.
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	let days = $state<number | null>(null);
	$effect(() => {
		days = settings.audit_retention_days;
	});

	let busy = $state(false);
	let error = $state<string | null>(null);
	let problem = $derived(retentionProblem(days ?? Number.NaN));
	let changed = $derived(days !== settings.audit_retention_days);
	let shorter = $derived(days !== null && problem === null && days < settings.audit_retention_days);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (problem || days === null) return;
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/general', {
					body: {
						session_lifetime_minutes: settings.session_lifetime_minutes,
						idle_timeout_minutes: settings.idle_timeout_minutes,
						audit_retention_days: days
					}
				})
			);
			notices.success('Audit retention saved.');
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Audit log</h2></Card.Title>
		<Card.Description>How long the <a class="underline" href="/admin/audit">audit log</a> keeps its entries.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="audit-retention-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="grid gap-2">
				<Label for="audit-retention">Keep entries for (days)</Label>
				<Input
					id="audit-retention"
					type="number"
					min={retentionRange.min}
					max={retentionRange.max}
					step="1"
					bind:value={days}
					class="w-40"
					aria-invalid={problem !== null}
					aria-describedby="audit-retention-hint"
				/>
				<p id="audit-retention-hint" class={problem ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
					{problem ?? `Entries older than ${describeRetention(days ?? 0)} are deleted once a day.`}
				</p>
				{#if shorter}
					<p class="text-sm text-amber-700 dark:text-amber-400">
						Entries older than {describeRetention(days ?? 0)} are deleted a few seconds after saving, and can't be brought back.
						Export them first if you need them.
					</p>
				{/if}
			</div>
		</form>
	</Card.Content>
	<Card.Footer class="flex flex-wrap items-center gap-3">
		<Button type="submit" form="audit-retention-form" disabled={busy || !changed || problem !== null}>
			{busy ? 'Saving…' : 'Save'}
		</Button>
		{#if !settings.updated_at}
			<p class="text-muted-foreground text-xs">The default: 365 days.</p>
		{/if}
	</Card.Footer>
</Card.Root>
