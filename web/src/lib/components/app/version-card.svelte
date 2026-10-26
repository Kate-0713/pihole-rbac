<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { displayVersion, type VersionInfo } from '#lib/system.js';

	let { version }: { version: VersionInfo } = $props();
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Version</h2></Card.Title>
		<Card.Description>The build this server is running.</Card.Description>
	</Card.Header>
	<Card.Content>
		<dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
			<dt class="text-muted-foreground">Version</dt>
			<dd class="flex flex-wrap items-center gap-2">
				<span data-testid="running-version">{displayVersion(version.version, version.development)}</span>
				{#if version.development}
					<Badge variant="outline" title="Not a release: it can't be compared with releases or updated from here">
						Development build
					</Badge>
				{/if}
			</dd>
			<dt class="text-muted-foreground">Commit</dt>
			<dd><code>{version.commit}</code></dd>
			<dt class="text-muted-foreground">Built</dt>
			<dd>{version.build_date}</dd>
		</dl>
	</Card.Content>
</Card.Root>
