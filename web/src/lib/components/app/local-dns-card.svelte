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
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { nameProblem } from '#lib/local-dns.js';
	import type { GeneralSettings } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// The local DNS settings: whether a change needs a reason, and the extra directory domains a name is checked
	// against. Like the other general settings, the save sends the session settings as they were loaded alongside it.
	let { settings, onsaved }: { settings: GeneralSettings; onsaved: () => Promise<void> | void } = $props();

	let required = $state(true);
	let domains = $state('');
	$effect(() => {
		required = settings.localdns_reason_required;
		domains = settings.localdns_extra_domains.join(', ');
	});

	// The domains as typed: separated by commas or spaces.
	let list = $derived(
		domains
			.split(/[\s,]+/)
			.map((d) => d.trim())
			.filter((d) => d !== '')
	);
	let problem = $derived.by(() => {
		if (list.length > 20) return 'At most 20 extra domains.';
		for (const d of list) {
			const p = nameProblem(d);
			if (p) return `${d}: ${p}`;
		}
		return null;
	});
	let changed = $derived(
		required !== settings.localdns_reason_required ||
			list.map((d) => d.toLowerCase()).join(',') !== settings.localdns_extra_domains.join(',')
	);

	let busy = $state(false);
	let error = $state<string | null>(null);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (problem) return;
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/general', {
					body: {
						session_lifetime_minutes: settings.session_lifetime_minutes,
						idle_timeout_minutes: settings.idle_timeout_minutes,
						localdns_reason_required: required,
						localdns_extra_domains: list
					}
				})
			);
			notices.success('Local DNS settings saved.');
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root role="region" aria-labelledby="local-dns-settings-title">
	<Card.Header>
		<Card.Title><h2 id="local-dns-settings-title">Local DNS</h2></Card.Title>
		<Card.Description>How changes to the Pi-holes' local DNS records and CNAMEs are made.</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="local-dns-settings-form" class="grid gap-4" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<div class="flex items-start gap-2">
				<Checkbox id="localdns-reason-required" bind:checked={required} disabled={busy} aria-describedby="localdns-reason-hint" />
				<div class="grid gap-1">
					<Label for="localdns-reason-required">Require a reason for every change</Label>
					<p id="localdns-reason-hint" class="text-muted-foreground text-sm">
						Pi-hole has nowhere to keep a note on a record, so the reason is kept in the audit log and shown beside the
						record.
					</p>
				</div>
			</div>
			<div class="grid gap-2">
				<Label for="localdns-extra-domains">Extra directory domains</Label>
				<Input
					id="localdns-extra-domains"
					bind:value={domains}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder="home.arpa, corp.example"
					disabled={busy}
					aria-invalid={problem !== null}
					aria-describedby="localdns-extra-domains-hint"
				/>
				<p id="localdns-extra-domains-hint" class={problem ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
					{problem ??
						"A name in one of these domains, or in the LDAP settings' base DN domain, needs confirming before it's saved: a local record there answers first, and can hide a real name. Separate them with commas."}
				</p>
			</div>
		</form>
	</Card.Content>
	<Card.Footer>
		<Button type="submit" form="local-dns-settings-form" disabled={busy || !changed || problem !== null}>
			{busy ? 'Saving…' : 'Save'}
		</Button>
	</Card.Footer>
</Card.Root>
