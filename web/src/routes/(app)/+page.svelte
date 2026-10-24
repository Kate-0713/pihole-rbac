<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { session } from '#lib/stores/session.svelte.js';
</script>

<svelte:head>
	<!-- Every page sets its own title: Svelte doesn't put back the previous one when a page goes away. -->
	<title>pihole-rbac</title>
</svelte:head>

<!-- Placeholder home page until the dashboard is built. -->
<h1 class="text-xl font-semibold">Welcome, {session.user?.username}</h1>
<p class="text-muted-foreground mt-2 text-sm">You're logged in. The dashboard comes next.</p>
