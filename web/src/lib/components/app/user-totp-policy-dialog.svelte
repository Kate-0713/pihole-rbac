<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { policyLabel, type TOTPPolicy } from '#lib/totp.js';
	import type { User } from '#lib/users.js';

	// A user's own two-factor setting, which wins over their roles': follow the roles, always required, or never
	// required. Requiring it applies at once: if they haven't set it up, their next request takes them to do so.
	let {
		open = $bindable(false),
		user,
		onsaved
	}: { open: boolean; user: User | null; onsaved: () => Promise<void> | void } = $props();

	const choices: { value: TOTPPolicy; hint: string }[] = [
		{ value: 'roles', hint: 'Required if any of their roles requires it.' },
		{ value: 'required', hint: 'Required whatever their roles say.' },
		{ value: 'exempt', hint: "Not required whatever their roles say. They can still turn it on themselves." }
	];

	let policy = $state<TOTPPolicy>('roles');
	let error = $state<string | null>(null);
	let busy = $state(false);

	$effect(() => {
		if (!open) return;
		policy = user?.totp_policy ?? 'roles';
		error = null;
	});

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!user) return;
		busy = true;
		error = null;
		try {
			await unwrap(api.PUT('/api/v1/users/{id}/totp-policy', { params: { path: { id: user.id } }, body: { policy } }));
			notices.success(`${user.username}: ${policyLabel(policy).toLowerCase()}.`);
			open = false;
			await onsaved();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Two-factor login for {user?.username}</Dialog.Title>
			<Dialog.Description>
				{user?.totp_enabled ? 'They have it on.' : "They haven't set it up."}
			</Dialog.Description>
		</Dialog.Header>
		<form id="user-totp-policy-form" class="grid gap-3" onsubmit={save}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			<!-- Plain radio inputs: bind:group ties the three to one $state variable. A fieldset and legend name the group
			     for screen readers. -->
			<fieldset class="grid gap-3">
				<legend class="sr-only">Whether {user?.username} must use two-factor login</legend>
				{#each choices as c (c.value)}
					<label class="flex items-start gap-2 text-sm">
						<input type="radio" name="totp-policy" value={c.value} bind:group={policy} class="mt-1" />
						<span class="grid gap-0.5">
							<span class="font-medium">{policyLabel(c.value)}</span>
							<span class="text-muted-foreground">{c.hint}</span>
						</span>
					</label>
				{/each}
			</fieldset>
		</form>
		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="user-totp-policy-form" disabled={busy || policy === user?.totp_policy}>
				{busy ? 'Saving…' : 'Save'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
