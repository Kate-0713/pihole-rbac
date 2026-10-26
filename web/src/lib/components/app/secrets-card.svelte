<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { describeReload, describeSource, secretKindLabel, type ReloadResult, type SecretStatus } from '#lib/system.js';

	// The secrets that come from the environment (config.reload): whether each is set and where from, never a value,
	// and Reload secrets, which re-reads every one given as a *_FILE variable.
	let { secrets, onreloaded }: { secrets: SecretStatus[]; onreloaded: () => Promise<void> | void } = $props();

	let busy = $state(false);
	let result = $state<ReloadResult | null>(null);

	async function reload() {
		busy = true;
		try {
			result = await unwrap(api.POST('/api/v1/system/reload'));
			if (result.session_ended) {
				// A new session key ends every session, this one included.
				notices.info('The session key changed, so everyone has to log in again.');
				session.expired();
				return;
			}
			if (result.failed.length === 0) notices.success(describeReload(result));
			await onreloaded();
		} catch (e) {
			notices.error(e, "Couldn't reload the secrets");
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Secrets</h2></Card.Title>
		<Card.Description>
			Secrets set in the environment or in files. A secret given as a file (<code>*_FILE</code>) is picked up by Reload
			secrets; one set directly in the environment needs a restart. Values are never shown.
		</Card.Description>
	</Card.Header>
	<Card.Content class="grid gap-3">
		{#if result && result.failed.length > 0}
			<Alert variant="destructive">
				<AlertDescription>
					<p>{describeReload(result)} The secrets that failed keep their previous value:</p>
					<ul class="mt-1 list-disc pl-5">
						{#each result.failed as f (f.name)}
							<li><code>{f.name}</code>: {f.message}</li>
						{/each}
					</ul>
				</AlertDescription>
			</Alert>
		{/if}
		<div class="overflow-x-auto rounded-md border">
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Variable</Table.Head>
						<Table.Head>What</Table.Head>
						<Table.Head>State</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each secrets as s (s.name)}
						<Table.Row data-secret={s.name}>
							<Table.Cell><code class="text-xs">{s.name}</code></Table.Cell>
							<Table.Cell>{secretKindLabel[s.kind]}</Table.Cell>
							<Table.Cell class="whitespace-normal">
								{#if s.set}
									<span class="text-sm">{describeSource(s)}</span>
								{:else}
									<Badge variant="outline">Not set</Badge>
								{/if}
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		</div>
	</Card.Content>
	<Card.Footer>
		<Button variant="outline" onclick={reload} disabled={busy}>{busy ? 'Reloading…' : 'Reload secrets'}</Button>
	</Card.Footer>
</Card.Root>
