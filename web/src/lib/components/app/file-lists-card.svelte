<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import type { GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Whether file: lists can be added. It's one of the general settings, which are saved together, so the save sends
	// the session settings as they were loaded alongside it.
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	let allow = $state(false);
	$effect(() => {
		allow = settings.allow_file_lists;
	});

	let busy = $state(false);
	let error = $state<string | null>(null);
	let changed = $derived(allow !== settings.allow_file_lists);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/general', {
					body: {
						session_lifetime_minutes: settings.session_lifetime_minutes,
						idle_timeout_minutes: settings.idle_timeout_minutes,
						allow_file_lists: allow
					}
				})
			);
			notices.success(allow ? 'file: lists can now be added.' : 'file: lists can no longer be added.');
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root role="region" aria-labelledby="file-lists-title">
	<Card.Header>
		<Card.Title><h2 id="file-lists-title">Lists</h2></Card.Title>
		<Card.Description>Which kinds of list address can be added to a Pi-hole.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="file-lists-form" class="grid gap-3" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="flex items-start gap-2">
				<Checkbox id="allow-file-lists" bind:checked={allow} disabled={busy} aria-describedby="allow-file-lists-hint" />
				<div class="grid gap-1">
					<Label for="allow-file-lists">Allow file: lists</Label>
					<p id="allow-file-lists-hint" class="text-muted-foreground text-sm">
						A file: list makes a Pi-hole read a file on its own host. Anyone with lists.edit could then point it at any
						file there. Turning this off doesn't remove file: lists already added; they're marked on the Lists page.
						Only http and https addresses are accepted otherwise.
					</p>
				</div>
			</div>
		</form>
	</Card.Content>
	<Card.Footer>
		<Button type="submit" form="file-lists-form" disabled={busy || !changed}>{busy ? 'Saving…' : 'Save'}</Button>
	</Card.Footer>
</Card.Root>
