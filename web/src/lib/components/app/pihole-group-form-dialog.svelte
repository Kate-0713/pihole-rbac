<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription, AlertTitle } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { commentProblem, type PiholeGroup } from '#lib/pihole.js';
	import {
		confirmationOf,
		defaultGroupID,
		nameProblem,
		renameSummary,
		type Confirmation
	} from '#lib/pihole-groups.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';
	import PiholeGroupReferences from './pihole-group-references.svelte';

	// One dialog for adding a Pi-hole group and for changing one's name and comment. Renaming a group the app refers
	// to is answered with 409 confirmation_required: the dialog then lists the references and offers to rename
	// anyway, which sends the same change with ?confirm=true. The Default group keeps its name.
	let {
		open = $bindable(false),
		target,
		targetName,
		group = null,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		group?: PiholeGroup | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let name = $state('');
	let comment = $state('');
	let error = $state<string | null>(null);
	let confirming = $state<Confirmation | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	// Fill the form each time the dialog opens; it reads only open and group, so typing doesn't reset it.
	$effect(() => {
		if (!open) return;
		name = group?.name ?? '';
		comment = group?.comment ?? '';
		error = null;
		confirming = null;
		touched = false;
	});

	let isDefault = $derived(group?.id === defaultGroupID);
	let nameHint = $derived(nameProblem(name));
	let commentHint = $derived(commentProblem(comment));
	let ready = $derived(nameHint === null && commentHint === null);
	// Any change to the fields drops a pending confirmation: it was for the change as it was.
	$effect(() => {
		void name;
		void comment;
		confirming = null;
	});

	async function save(event?: SubmitEvent) {
		event?.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const confirm = confirming !== null;
		const params = (members?: number[]) => ({
			params: { path: { target }, query: { ...(members ? { members } : {}), ...(confirm ? { confirm: true } : {}) } }
		});
		try {
			if (group) {
				const body = {
					name: group.name,
					...(name !== group.name ? { new_name: name } : {}),
					...(comment !== group.comment ? { comment } : {})
				};
				if (!body.new_name && body.comment === undefined) {
					open = false;
					return;
				}
				const send = async (members?: number[]) =>
					await unwrap(api.PATCH('/api/v1/targets/{target}/groups', { ...params(members), body }));
				const res = await send();
				reportResults(
					res.results,
					{ done: `${name} saved`, failed: `Couldn't change ${group.name}` },
					{ retry: async (m) => (await send(m)).results, after: onsaved }
				);
				const refs = renameSummary(res.references);
				if (refs) notices.info(refs);
			} else {
				const body = { name, comment, enabled: true };
				const send = async (members?: number[]) =>
					(await unwrap(api.POST('/api/v1/targets/{target}/groups', { ...params(members), body }))).results;
				reportResults(
					await send(),
					{ done: `${name} added`, failed: `Couldn't add ${name}` },
					{ retry: send, after: onsaved }
				);
			}
			open = false;
			await onsaved();
		} catch (e) {
			const c = confirmationOf(e);
			if (c) {
				confirming = c;
			} else {
				// Shown in the dialog, which stays open, so the change can be fixed and saved again.
				error = failureMessage(e);
			}
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{group ? 'Change Pi-hole group' : 'Add a Pi-hole group'}</Dialog.Title>
			<Dialog.Description>
				{#if group}
					<span class="font-medium break-all">{group.name}</span> on {targetName}.
				{:else}
					Add a Pi-hole group to {targetName}. Domains, clients and lists can then be put in it.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="pihole-group-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			{#if confirming}
				<Alert>
					<AlertTitle>The app refers to {group?.name ?? 'this group'}</AlertTitle>
					<AlertDescription>
						<p>
							Renaming it updates the references by exact name where the old name is gone, and lists the rest for you to
							check.
						</p>
						{#if confirming.references}<PiholeGroupReferences refs={confirming.references} label="References" />{/if}
					</AlertDescription>
				</Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="pihole-group-name">Name</Label>
				<Input
					id="pihole-group-name"
					bind:value={name}
					autocomplete="off"
					spellcheck={false}
					disabled={isDefault}
					aria-invalid={touched && nameHint !== null}
					aria-describedby="pihole-group-name-hint"
				/>
				{#if isDefault}
					<p id="pihole-group-name-hint" class="text-muted-foreground text-sm">The Default group can't be renamed.</p>
				{:else if touched && nameHint}
					<p id="pihole-group-name-hint" class="text-destructive text-sm">{nameHint}</p>
				{/if}
			</div>

			<div class="grid gap-2">
				<Label for="pihole-group-comment">Comment</Label>
				<Input
					id="pihole-group-comment"
					bind:value={comment}
					autocomplete="off"
					aria-invalid={commentHint !== null}
					aria-describedby="pihole-group-comment-hint"
				/>
				{#if commentHint}
					<p id="pihole-group-comment-hint" class="text-destructive text-sm">{commentHint}</p>
				{/if}
			</div>
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="pihole-group-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if confirming}Rename anyway{:else if group}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
