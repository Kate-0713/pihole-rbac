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
	import { addressProblem, typeLabel, type ListType, type PiholeList } from '#lib/lists.js';
	import { commentProblem, type PiholeGroup } from '#lib/pihole.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';
	import GroupPicker from './group-picker.svelte';

	// One dialog for subscribing to a list and for changing one. With `list`, it changes its comment and groups (its
	// address and type name it, so they can't change); without, it adds a new one.
	let {
		open = $bindable(false),
		target,
		targetName,
		groups,
		list = null,
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		groups: PiholeGroup[];
		list?: PiholeList | null;
		onsaved: () => Promise<void> | void;
	} = $props();

	let address = $state('');
	let type = $state<ListType>('block');
	let comment = $state('');
	let selected = $state<number[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);

	// Filled each time the dialog opens; it reads only open, list and groups, so typing doesn't reset it.
	$effect(() => {
		if (!open) return;
		address = list?.address ?? '';
		type = list?.type ?? 'block';
		comment = list?.comment ?? '';
		selected = list ? [...list.groups] : groups.some((g) => g.id === 0) ? [0] : [];
		error = null;
		touched = false;
	});

	let editing = $derived(list !== null);
	// The page doesn't know allow_file_lists (only admins can read the settings), so a file: address is left to the
	// server to accept or refuse.
	let addressHint = $derived.by(() => {
		if (editing) return null;
		const hint = addressProblem(address, true);
		return hint;
	});
	let commentHint = $derived(commentProblem(comment));
	let ready = $derived(addressHint === null && commentHint === null);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const params = (members?: number[]) => ({ params: { path: { target }, query: members ? { members } : undefined } });
		try {
			if (list) {
				const body = { address: list.address, type: list.type, comment, groups: selected };
				const send = async (members?: number[]) =>
					(await unwrap(api.PATCH('/api/v1/targets/{target}/lists', { ...params(members), body }))).results;
				reportResults(
					await send(),
					{ done: `${list.address} updated`, failed: `Couldn't update ${list.address}` },
					{ retry: send, after: onsaved }
				);
			} else {
				const a = address.trim();
				const body = { address: a, type, comment, groups: selected, enabled: true };
				const send = async (members?: number[]) =>
					(await unwrap(api.POST('/api/v1/targets/{target}/lists', { ...params(members), body }))).results;
				const results = await send();
				reportResults(results, { done: `${a} added`, failed: `Couldn't add ${a}` }, { retry: send, after: onsaved });
				if (results.some((r) => r.status === 'ok')) notices.info('Pi-hole starts using it after the next gravity update.');
			}
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
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{editing ? 'Change list' : 'Add a list'}</Dialog.Title>
			<Dialog.Description>
				{#if list}
					<span class="font-mono break-all">{list.address}</span>, a {typeLabel[list.type].toLowerCase()} of {targetName}.
					A change to its groups applies at once.
				{:else}
					Subscribe {targetName} to a blocklist or allowlist. Pi-hole downloads it at the next gravity update.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="list-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}

			{#if !editing}
				<div class="grid gap-2">
					<Label for="list-address">Address</Label>
					<Input
						id="list-address"
						bind:value={address}
						class="font-mono"
						autocomplete="off"
						spellcheck={false}
						inputmode="url"
						placeholder="https://lists.example/hosts.txt"
						aria-invalid={touched && addressHint !== null}
						aria-describedby="list-address-hint"
					/>
					<p id="list-address-hint" class={touched && addressHint ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}>
						{touched && addressHint
							? addressHint
							: 'Everyone who can see the lists sees the address, so don\'t put a password or a private token in it.'}
					</p>
				</div>

				<div class="grid gap-2">
					<Label for="list-type">Type</Label>
					<Select.Root type="single" bind:value={type}>
						<Select.Trigger id="list-type" class="w-full sm:w-56">{typeLabel[type]}</Select.Trigger>
						<Select.Content>
							<Select.Item value="block" label="Blocklist">Blocklist (block its domains)</Select.Item>
							<Select.Item value="allow" label="Allowlist">Allowlist (allow its domains)</Select.Item>
						</Select.Content>
					</Select.Root>
				</div>
			{/if}

			<div class="grid gap-2">
				<Label for="list-comment">Comment</Label>
				<Input
					id="list-comment"
					bind:value={comment}
					autocomplete="off"
					aria-invalid={commentHint !== null}
					aria-describedby="list-comment-hint"
				/>
				{#if commentHint}
					<p id="list-comment-hint" class="text-destructive text-sm">{commentHint}</p>
				{/if}
			</div>

			<GroupPicker {groups} bind:selected idPrefix="list" disabled={busy} />
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="list-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if editing}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
