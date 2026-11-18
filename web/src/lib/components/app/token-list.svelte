<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { summarise, type Catalogue } from '#lib/roles.js';
	import { expiresSoon, refusedNote, revokedText, stateLabel, suspendedNote, type APIToken } from '#lib/tokens.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// A list of API tokens, newest first, with what each can do and when it was last used. `admin` is the admin tab:
	// it shows each token's owner and revokes through /tokens; otherwise these are the caller's own. Revoking always
	// asks first, since a script using the token stops at once. `catalogue` names the instances and groups in the
	// grants; without it they are shown by ID.
	let {
		tokens,
		admin,
		catalogue,
		onchanged
	}: { tokens: APIToken[]; admin: boolean; catalogue: Catalogue | null; onchanged: () => Promise<void> | void } = $props();

	let asking = $state<APIToken | null>(null);
	let askOpen = $state(false);
	let busy = $state(false);
	let error = $state<string | null>(null);
	const now = new Date();

	function ask(t: APIToken) {
		asking = t;
		error = null;
		askOpen = true;
	}

	async function revoke(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open until the answer is known
		if (!asking) return;
		busy = true;
		error = null;
		const path = { params: { path: { public_id: asking.public_id } } };
		try {
			await unwrap(admin ? api.DELETE('/api/v1/tokens/{public_id}', path) : api.DELETE('/api/v1/account/tokens/{public_id}', path));
			notices.success(admin ? `${asking.username}'s token "${asking.name}" revoked.` : `Token "${asking.name}" revoked.`);
			askOpen = false;
			await onchanged();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
		} finally {
			busy = false;
		}
	}
</script>

{#if tokens.length === 0}
	<p class="text-muted-foreground text-sm">{admin ? 'Nobody has an API token.' : "You don't have any API tokens."}</p>
{:else}
	<!-- A list rather than a table, as for sessions: each token has several lines of detail. -->
	<ul class="divide-y rounded-md border" aria-label="API tokens">
		{#each tokens as t (t.public_id)}
			<!-- Expired and revoked tokens are dimmed: they are history. A suspended one isn't: it comes back by itself.
			     The row doesn't wrap: the details take the room beside Revoke, so a long note wraps within them and the
			     button stays at the top right. -->
			<li
				class="flex items-start justify-between gap-4 p-3"
				class:opacity-60={t.state === 'expired' || t.state === 'revoked'}
			>
				<div class="grid min-w-0 flex-1 gap-1 text-sm">
					<p class="font-medium">
						{admin ? `${t.username} · ${t.name}` : t.name}
						<Badge
							variant={t.state === 'active' && !t.refused ? 'secondary' : t.state === 'active' || t.state === 'suspended' ? 'destructive' : 'outline'}
							class="ml-1">{stateLabel(t)}</Badge
						>
						{#if expiresSoon(t, now)}<Badge variant="destructive" class="ml-1">Expires soon</Badge>{/if}
					</p>
					{#if t.state === 'suspended'}
						<p class="text-destructive">{suspendedNote(t, admin)}</p>
					{/if}
					<!-- Refused, not revoked: the owner's account stops it, and it works again once that changes. -->
					{#if refusedNote(t, admin)}
						<p class="text-destructive">{refusedNote(t, admin)}</p>
					{/if}
					<ul class="text-muted-foreground font-mono text-xs">
						{#each summarise(t.grants, catalogue) as line (line)}
							<li>{line}</li>
						{/each}
					</ul>
					<p class="text-muted-foreground">
						{#if t.state === 'revoked'}
							{revokedText(t, admin)}, {formatDateTime(t.revoked_at)}
						{:else}
							{t.state === 'expired' ? 'Expired' : 'Expires'} {formatDateTime(t.expires_at)}
						{/if}
						· made {formatDateTime(t.created_at)} ·
						{t.last_used_at ? `last used ${formatDateTime(t.last_used_at)} from ${t.last_used_ip}` : 'never used'}
					</p>
				</div>
				{#if t.state === 'active' || t.state === 'suspended'}
					<Button variant="outline" size="sm" class="shrink-0" onclick={() => ask(t)} aria-label="Revoke {admin ? `${t.username}'s ` : ''}token {t.name}">
						Revoke
					</Button>
				{/if}
			</li>
		{/each}
	</ul>
{/if}

<AlertDialog.Root bind:open={askOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Revoke {admin ? `${asking?.username}'s token` : 'the token'} "{asking?.name}"?</AlertDialog.Title>
			<AlertDialog.Description>
				It stops working at once, and anything using it gets "invalid token" from now on. This can't be undone: make a new
				token if it's needed again.
			</AlertDialog.Description>
		</AlertDialog.Header>
		{#if error}
			<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={revoke}>
				{busy ? 'Revoking…' : 'Revoke'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
