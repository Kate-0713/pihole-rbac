<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { updated } from '$app/state';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';

	// The server has a newer build of these pages than the one this tab is running (after an update, say). The root
	// layout asks about it; this only says so. Moving to another page reloads anyway, so this matters most for someone
	// who stays on one page, and it is never forced: a half-filled form isn't lost.
</script>

{#if updated.current}
	<Alert aria-label="New version">
		<AlertDescription class="flex flex-wrap items-center gap-3">
			<span>pihole-rbac has been updated since this page was loaded. Reload to use the new version.</span>
			<Button size="sm" variant="outline" onclick={() => location.reload()}>Reload</Button>
		</AlertDescription>
	</Alert>
{/if}
