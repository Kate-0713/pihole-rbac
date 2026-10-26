<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import XIcon from '@lucide/svelte/icons/x';
	import { page } from '$app/state';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { can } from '#lib/permissions.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { updates } from '#lib/stores/updates.svelte.js';
	import { bannerVersion, displayVersion } from '#lib/system.js';

	// Tells people who can update (app.update) that a newer release is out. Everyone else never asks for the status.
	// The status is read once per login; the System page keeps it current.
	let allowed = $derived(can('app.update'));
	$effect(() => {
		const id = session.user?.id;
		if (id !== undefined && allowed) void updates.ensure(id);
	});

	// Not on the System page, which says the same thing in more detail.
	let version = $derived(
		allowed && page.url.pathname !== '/admin/system' ? bannerVersion(updates.status, updates.dismissed) : null
	);
	let running = $derived(
		updates.status ? displayVersion(updates.status.current_version, updates.status.development) : ''
	);
</script>

{#if version && updates.status?.latest}
	<Alert class="pr-12" aria-label="Update available">
		<AlertDescription class="flex flex-wrap items-center gap-x-3 gap-y-1">
			<span>pihole-rbac <strong>{version}</strong> is available (this is {running}).</span>
			<a class="underline" href={updates.status.latest.url} target="_blank" rel="noopener noreferrer">What's new</a>
			<a class="underline" href="/admin/system">Update on the System page</a>
		</AlertDescription>
		<Button
			variant="ghost"
			size="icon-sm"
			class="absolute top-1.5 right-1.5"
			aria-label="Dismiss until the next release"
			onclick={() => updates.dismiss(version!)}
		>
			<XIcon />
		</Button>
	</Alert>
{/if}
