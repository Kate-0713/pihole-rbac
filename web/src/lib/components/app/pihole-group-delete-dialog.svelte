<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import type { PiholeGroup } from '#lib/pihole.js';
	import { confirmationOf, countText, referenceCount, type GroupUsage } from '#lib/pihole-groups.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';
	import PiholeGroupReferences from './pihole-group-references.svelte';

	// Asks before deleting a Pi-hole group, saying what uses it: Pi-hole takes it off every domain, client and list,
	// and the app's references to it are left for someone to fix. The usage is read when the dialog opens, just before
	// asking. When it lists references, the delete is sent with ?confirm=true, since the question was just answered.
	let {
		open = $bindable(false),
		target,
		targetName,
		group,
		ondeleted
	}: {
		open: boolean;
		target: string;
		targetName: string;
		group: PiholeGroup | null;
		ondeleted: () => Promise<void> | void;
	} = $props();

	let usage = $state<GroupUsage | null>(null);
	let usageError = $state<string | null>(null);
	let busy = $state(false);

	// Read the usage each time the dialog opens for a group. The request is started from the effect but its result
	// only lands if the dialog is still open for the same group.
	$effect(() => {
		if (!open || !group) return;
		const name = group.name;
		usage = null;
		usageError = null;
		unwrap(api.GET('/api/v1/targets/{target}/groups/usage', { params: { path: { target }, query: { name } } }))
			.then((u) => {
				if (open && group?.name === name) usage = u;
			})
			.catch((e: unknown) => {
				if (open && group?.name === name) usageError = e instanceof Error ? e.message : "Couldn't read what uses it.";
			});
	});

	const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

	async function remove(event: MouseEvent) {
		event.preventDefault();
		if (!group) return;
		busy = true;
		const name = group.name;
		const text = { done: `${name} deleted`, failed: `Couldn't delete ${name}` };
		const confirm = referenceCount(usage?.references) > 0;
		const refs = usage?.references;
		const send = async (members?: number[]) =>
			(
				await unwrap(
					api.DELETE('/api/v1/targets/{target}/groups', {
						params: { path: { target }, query: { ...(members ? { members } : {}), ...(confirm ? { confirm: true } : {}) } },
						body: { name }
					})
				)
			).results;
		const retry = { retry: send, after: ondeleted };
		try {
			reportResults(await send(), text, retry);
			if (confirm && refs) notices.info(`The app still refers to ${name}: ${countText(refs)}. They're left for you to fix.`);
		} catch (e) {
			// References added since the dialog opened: say so rather than delete without asking again.
			if (confirmationOf(e)) notices.error('The app now refers to this group. Open the dialog again to see how.', text.failed);
			else reportFailure(e, text, retry);
		} finally {
			busy = false;
			open = false;
			await ondeleted();
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Delete this Pi-hole group?</AlertDialog.Title>
			<AlertDialog.Description>
				{#if group}
					<span class="text-foreground font-medium break-all">{group.name}</span> is deleted from {targetName}, and Pi-hole
					takes it off every domain, client and list. Pi-hole can't undo this.
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<div class="grid gap-2 text-sm" aria-live="polite">
			{#if usageError}
				<p class="text-destructive">Couldn't read what uses it: {usageError}</p>
			{:else if !usage}
				<p class="text-muted-foreground">Reading what uses it…</p>
			{:else}
				<p data-usage>
					In this group: {plural(usage.domains, 'domain', 'domains')}, {plural(usage.clients, 'client', 'clients')} and
					{plural(usage.lists, 'list', 'lists')}. A client only in this group is left in none.
				</p>
				{#if referenceCount(usage.references) > 0}
					<PiholeGroupReferences refs={usage.references} label="The app refers to it" />
					<p class="text-muted-foreground">These are left as they are, for you to fix.</p>
				{/if}
			{/if}
		</div>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action
				class={buttonVariants({ variant: 'destructive' })}
				disabled={busy || (!usage && !usageError)}
				onclick={remove}
			>
				{busy ? 'Deleting…' : referenceCount(usage?.references) > 0 ? 'Delete anyway' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
