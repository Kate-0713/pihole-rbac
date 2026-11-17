<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import type { Role } from '#lib/roles.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';

	// Whether a role's holders must use two-factor login. Saved as soon as it is ticked, apart from the role's other
	// settings: it applies at once, and a holder without it is taken to set it up on their next request. The builtin
	// admin role can require it too. A role the caller can't change has the box disabled; the editor above says why.
	let { role }: { role: Role } = $props();

	let busy = $state(false);
	let error = $state<string | null>(null);
	// The box's own state, so it can be put back if the server refuses. The effect copies the saved value in whenever
	// the role is read again (it reads role.totp_required, so it runs when that changes).
	let checked = $state(false);
	$effect(() => {
		checked = role.totp_required;
	});

	async function set(required: boolean) {
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/roles/{id}/totp-required', { params: { path: { id: role.id } }, body: { required } })
			);
			notices.success(required ? `Holders of ${role.name} must now use two-factor login.` : `${role.name} no longer requires two-factor login.`);
			// You may hold the role yourself: refresh() takes you to set it up if so. invalidateAll() reloads the page's
			// data, so the box shows what was saved.
			await session.refresh();
			await invalidateAll();
		} catch (e) {
			checked = role.totp_required;
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Two-factor login</Card.Title>
	</Card.Header>
	<Card.Content class="grid gap-3">
		{#if error}
			<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
		{/if}
		<div class="flex items-start gap-3">
			<!-- onCheckedChange runs after bind:checked has changed `checked`, and asks the server to save it. -->
			<Checkbox
				id="role-totp-required"
				bind:checked
				disabled={busy || !role.manageable}
				onCheckedChange={(v) => set(v === true)}
				aria-describedby="role-totp-required-hint"
			/>
			<div class="grid gap-1">
				<Label for="role-totp-required">Require two-factor login</Label>
				<p id="role-totp-required-hint" class="text-muted-foreground text-sm">
					Everyone with this role must use a code from an authenticator app after their password. Anyone who hasn't set
					it up is taken to do so on their next request, and can do nothing else until they have. A user's own setting
					on the Users page wins over this.
				</p>
			</div>
		</div>
	</Card.Content>
</Card.Root>
