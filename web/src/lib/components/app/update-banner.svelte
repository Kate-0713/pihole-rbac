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

	// Tells everyone that a newer release is out. People who can update (app.update) read the full status and get a
	// link to the System page; everyone else reads only the version endpoint and is told an administrator can
	// install it. Read once per login; the System page keeps it current.
	let canUpdate = $derived(can('app.update'));
	$effect(() => {
		const id = session.user?.id;
		if (id !== undefined) void updates.ensure(id, canUpdate);
	});

	// Not on the System page, which says the same thing in more detail. Dismissing hides a release for the rest of
	// this session only (see updates.dismissedFor), so the banner is back at the next login.
	let sessionId = $derived(session.current?.public_id);
	let version = $derived(
		page.url.pathname !== '/admin/system'
			? bannerVersion(updates.banner, updates.dismissedFor(sessionId))
			: null
	);
	let running = $derived(
		updates.banner ? displayVersion(updates.banner.current_version, updates.banner.development) : ''
	);
</script>

{#if version && updates.banner?.latest}
	<Alert class="pr-12" aria-label="Update available">
		<AlertDescription class="flex flex-wrap items-center gap-x-3 gap-y-1">
			<span>
				pihole-rbac <strong>{version}</strong> is available (this is {running}).{#if !canUpdate}{' '}An
					administrator can install it.{/if}
			</span>
			<a class="underline" href={updates.banner.latest.url} target="_blank" rel="noopener noreferrer">What's new</a>
			{#if canUpdate}
				<a class="underline" href="/admin/system">Update on the System page</a>
			{/if}
		</AlertDescription>
		<Button
			variant="ghost"
			size="icon-sm"
			class="absolute top-1.5 right-1.5"
			aria-label="Dismiss until you next log in"
			onclick={() => sessionId && updates.dismiss(version!, sessionId)}
		>
			<XIcon />
		</Button>
	</Alert>
{/if}
