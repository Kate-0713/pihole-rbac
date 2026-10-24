<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { domainProblem, kindLabel, typeLabel, type Domain, type DomainKind, type DomainType } from '#lib/domains.js';
	import { commentProblem, type PiholeGroup } from '#lib/pihole.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';
	import GroupPicker from './group-picker.svelte';

	// One dialog for adding an entry and for changing one. With `entry`, it edits that entry's groups and comment (its
	// domain, list and kind name it, so they can't change); without, it adds a new one.
	let {
		open = $bindable(false),
		target,
		targetName,
		groups,
		entry = null,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		groups: PiholeGroup[];
		entry?: Domain | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let domain = $state('');
	let type = $state<DomainType>('deny');
	let kind = $state<DomainKind>('exact');
	let comment = $state('');
	let selected = $state<number[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);
	// Hints wait until the user has typed, or tried to save, so an empty new form isn't already in the red.
	let touched = $state(false);

	// Fill the form each time the dialog opens. An $effect reruns when anything it reads changes: this one reads only
	// open, entry and groups, never the fields it sets, so typing doesn't reset the form.
	$effect(() => {
		if (!open) return;
		domain = entry?.domain ?? '';
		type = entry?.type ?? 'deny';
		kind = entry?.kind ?? 'exact';
		comment = entry?.comment ?? '';
		// A new entry goes in the Default group, as in Pi-hole's own interface.
		selected = entry ? [...entry.groups] : groups.some((g) => g.id === 0) ? [0] : [];
		error = null;
		touched = false;
	});

	let editing = $derived(entry !== null);
	let domainHint = $derived(editing ? null : domainProblem(domain, kind));
	let commentHint = $derived(commentProblem(comment));
	let ready = $derived(domainHint === null && commentHint === null);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const params = { params: { path: { target } } };
		try {
			if (entry) {
				const { results } = await unwrap(
					api.PATCH('/api/v1/targets/{target}/domains', {
						...params,
						body: { domain: entry.domain, type: entry.type, kind: entry.kind, comment, groups: selected }
					})
				);
				reportResults(results, { done: `${entry.domain} updated`, failed: `Couldn't update ${entry.domain}` });
			} else {
				const d = domain.trim();
				const { results } = await unwrap(
					api.POST('/api/v1/targets/{target}/domains', {
						...params,
						body: { domain: d, type, kind, comment, groups: selected }
					})
				);
				reportResults(results, {
					done: `${d} added to the ${type} list`,
					failed: `Couldn't add ${d}`
				});
			}
			open = false;
			await onsaved();
		} catch (e) {
			// Shown in the dialog, which stays open, so the entry can be fixed and saved again.
			error = failureMessage(e);
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{editing ? 'Change entry' : 'Add a domain'}</Dialog.Title>
			<Dialog.Description>
				{#if entry}
					<span class="font-mono break-all">{entry.domain}</span> on the {typeLabel[entry.type].toLowerCase()} list
					({kindLabel[entry.kind].toLowerCase()}) of {targetName}.
				{:else}
					Add an entry to the allow or deny list of {targetName}.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="domain-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}

			{#if !editing}
				<div class="grid gap-2">
					<Label for="domain-input">{kind === 'regex' ? 'Regular expression' : 'Domain'}</Label>
					<Input
						id="domain-input"
						bind:value={domain}
						class="font-mono"
						autocomplete="off"
						spellcheck={false}
						placeholder={kind === 'regex' ? '(^|\\.)example\\.com$' : 'ads.example.com'}
						aria-invalid={touched && domainHint !== null}
						aria-describedby="domain-hint"
					/>
					{#if touched && domainHint}
						<p id="domain-hint" class="text-destructive text-sm">{domainHint}</p>
					{/if}
				</div>

				<div class="grid gap-4 sm:grid-cols-2">
					<div class="grid gap-2">
						<Label for="domain-type">List</Label>
						<Select.Root type="single" bind:value={type}>
							<Select.Trigger id="domain-type" class="w-full">{typeLabel[type]}</Select.Trigger>
							<Select.Content>
								<Select.Item value="deny" label="Deny">Deny (block)</Select.Item>
								<Select.Item value="allow" label="Allow">Allow</Select.Item>
							</Select.Content>
						</Select.Root>
					</div>
					<div class="grid gap-2">
						<Label for="domain-kind">Match</Label>
						<Select.Root type="single" bind:value={kind}>
							<Select.Trigger id="domain-kind" class="w-full">{kindLabel[kind]}</Select.Trigger>
							<Select.Content>
								<Select.Item value="exact" label="Exact">Exact domain</Select.Item>
								<Select.Item value="regex" label="Regex">Regular expression</Select.Item>
							</Select.Content>
						</Select.Root>
					</div>
				</div>
			{/if}

			<div class="grid gap-2">
				<Label for="domain-comment">Comment</Label>
				<Input
					id="domain-comment"
					bind:value={comment}
					autocomplete="off"
					aria-invalid={commentHint !== null}
					aria-describedby="comment-hint"
				/>
				{#if commentHint}
					<p id="comment-hint" class="text-destructive text-sm">{commentHint}</p>
				{/if}
			</div>

			<GroupPicker {groups} bind:selected idPrefix="domain" disabled={busy} />
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="domain-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if editing}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
