<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '#lib/components/ui/button/index.js';
	import { ApiError } from '#lib/api/client.js';
	import { session } from '#lib/stores/session.svelte.js';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	let loggingOut = $state(false);
	let logoutError = $state<string | null>(null);

	async function logout() {
		loggingOut = true;
		logoutError = null;
		try {
			await session.logout();
			await goto('/login', { replaceState: true });
		} catch (e) {
			logoutError = e instanceof ApiError ? e.message : "Couldn't log out. Try again.";
		} finally {
			loggingOut = false;
		}
	}
</script>

<!-- A minimal header for now; the navigation and target picker join it next. -->
<header class="border-b">
	<div class="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4">
		<a href="/" class="font-semibold">pihole-rbac</a>
		<div class="ml-auto flex items-center gap-3">
			{#if logoutError}
				<span class="text-destructive text-sm" role="alert">{logoutError}</span>
			{/if}
			<span class="text-muted-foreground text-sm">{session.user?.username}</span>
			<Button variant="outline" size="sm" onclick={logout} disabled={loggingOut}>Log out</Button>
		</div>
	</div>
</header>

<main class="mx-auto w-full max-w-6xl flex-1 p-4">
	{@render children()}
</main>
