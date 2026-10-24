<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { matchedGroups, testVerdict, type UserTest } from '#lib/ldap.js';

	// Asks the directory about a username with the service account (no password) and shows what logging in would give
	// them: their groups, the mappings those match, the roles and the permissions. For finding out why someone can't
	// log in, or checking a new mapping.
	let username = $state('');
	let busy = $state(false);
	let error = $state<{ message: string; detail?: string } | null>(null);
	let result = $state<UserTest | null>(null);

	let verdict = $derived(result ? testVerdict(result) : null);
	let matched = $derived(result ? matchedGroups(result) : new Set<string>());

	async function run(event: SubmitEvent) {
		event.preventDefault();
		if (username.trim() === '') return;
		busy = true;
		error = null;
		result = null;
		try {
			result = await unwrap(api.POST('/api/v1/ldap/test-user', { body: { username: username.trim() } }));
		} catch (e) {
			if (e instanceof ApiError) {
				error = { message: e.message, detail: typeof e.details.detail === 'string' ? e.details.detail : undefined };
			} else {
				error = { message: 'Something went wrong. Try again.' };
			}
		} finally {
			busy = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Test a user</h2></Card.Title>
		<Card.Description>
			Look someone up in the directory, without their password, and see what logging in would give them.
		</Card.Description>
	</Card.Header>
	<Card.Content class="grid gap-4">
		<form class="flex flex-wrap items-end gap-3" onsubmit={run}>
			<div class="grid gap-2">
				<Label for="test-username">Username</Label>
				<Input id="test-username" bind:value={username} autocomplete="off" autocapitalize="none" spellcheck={false} class="w-56" />
			</div>
			<Button type="submit" variant="outline" disabled={busy || username.trim() === ''}>{busy ? 'Looking up…' : 'Look up'}</Button>
		</form>

		{#if error}
			<Alert variant="destructive">
				<AlertDescription>
					<p>{error.message}</p>
					{#if error.detail}<p class="font-mono text-xs break-all">{error.detail}</p>{/if}
				</AlertDescription>
			</Alert>
		{/if}

		{#if result && verdict}
			<!-- role="status" makes a screen reader announce the result when it appears. -->
			<div class="grid gap-3" role="status">
				<p class={verdict.tone === 'ok' ? 'font-medium' : 'text-destructive font-medium'}>{verdict.text}</p>
				{#if result.found}
					<dl class="grid gap-3 text-sm sm:grid-cols-[8rem_1fr]">
						<dt class="text-muted-foreground">DN</dt>
						<dd class="font-mono text-xs break-all">{result.dn}</dd>
						<dt class="text-muted-foreground">Groups</dt>
						<dd>
							{#if result.groups.length === 0}
								<span class="text-muted-foreground">None</span>
							{:else}
								<ul class="grid gap-1">
									{#each result.groups as g (g)}
										<li class="font-mono text-xs break-all">
											{g}
											{#if matched.has(g)}<Badge variant="secondary" class="ml-1 font-sans">mapped</Badge>{/if}
										</li>
									{/each}
								</ul>
							{/if}
						</dd>
						{#if result.roles.length > 0}
							<dt class="text-muted-foreground">Permissions</dt>
							<dd class="grid gap-1">
								{#if result.permissions.global.length > 0}
									<p><span class="text-muted-foreground">Everywhere:</span> {result.permissions.global.join(', ')}</p>
								{/if}
								{#each result.permissions.targets as t (t.target)}
									<p><span class="text-muted-foreground">{t.name}:</span> {t.permissions.join(', ')}</p>
								{/each}
							</dd>
						{/if}
					</dl>
				{/if}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
