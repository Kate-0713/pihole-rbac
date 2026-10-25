<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ClientResetRulesDialog from '#lib/components/app/client-reset-rules-dialog.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { byScope, describeRule, type Rules } from '#lib/clientreset.js';

	// The rules, by the instance or mirrored group they're set on, and the dialog that edits them.
	let { settings, onsaved }: { settings: Rules; onsaved: () => Promise<void> | void } = $props();

	let open = $state(false);
	let scopes = $derived(byScope(settings.rules));
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Rules</h2></Card.Title>
		<Card.Description>Which clients go back to which Pi-hole groups, by the start of their comment.</Card.Description>
		<Card.Action>
			<Button variant="outline" size="sm" onclick={() => (open = true)}>Edit rules</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content>
		{#if scopes.length === 0}
			<p class="text-muted-foreground text-sm">No rules yet, so nothing is reset.</p>
		{:else}
			<ul class="grid gap-3 text-sm" aria-label="Rules">
				{#each scopes as s (s.key)}
					<li class="grid gap-1">
						<p>
							<span class="font-medium">{s.name}</span>
							<span class="text-muted-foreground text-xs">{s.scope === 'group' ? 'mirrored group' : 'instance'}</span>
						</p>
						<ul class="grid gap-0.5 pl-3">
							{#each s.rules as r (r.comment_prefix)}
								<li class="font-mono text-xs">{describeRule(r)}</li>
							{/each}
						</ul>
					</li>
				{/each}
			</ul>
			<p class="text-muted-foreground mt-3 text-xs">A group name ending in … is a prefix: every Pi-hole group starting with it.</p>
		{/if}
	</Card.Content>
</Card.Root>

<ClientResetRulesDialog bind:open {settings} {onsaved} />
