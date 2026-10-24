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
	import { describeAgent, type SessionInfo, type SessionList } from '#lib/sessions.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';

	// A list of sessions, newest first, with a button to end each one. `first` is the first page, read by the page's
	// load; "Show more" reads the next pages here. After a session is ended, onchanged reads the list again. Ending
	// another user's session, or your own current one, asks first.
	let {
		first,
		mine,
		onchanged
	}: { first: SessionList; mine: boolean; onchanged: () => Promise<void> | void } = $props();

	// The pages read with "Show more", after the first. They start again whenever the first page changes.
	let more = $state<SessionInfo[]>([]);
	let cursor = $state<string | undefined>(undefined);
	$effect(() => {
		more = [];
		cursor = first.next_cursor;
	});
	let loading = $state(false);
	let rows = $derived([...first.sessions, ...more]);
	let others = $derived(rows.filter((s) => !s.current && s.user.id === session.user?.id));

	let asking = $state<SessionInfo | null>(null);
	let askOpen = $state(false);
	let busy = $state<string | null>(null);
	let error = $state<string | null>(null);

	async function showMore() {
		if (!cursor) return;
		loading = true;
		try {
			const page = await unwrap(api.GET('/api/v1/sessions', { params: { query: { cursor, mine } } }));
			more = [...more, ...page.sessions];
			cursor = page.next_cursor;
		} catch (e) {
			notices.error(e, "Couldn't read more sessions");
		} finally {
			loading = false;
		}
	}

	function end(s: SessionInfo) {
		// Your own other sessions go at once; the rest ask first.
		if (!s.current && s.user.id === session.user?.id) {
			void revoke(s);
			return;
		}
		asking = s;
		askOpen = true;
	}

	async function revoke(s: SessionInfo): Promise<boolean> {
		busy = s.public_id;
		error = null;
		try {
			await unwrap(api.DELETE('/api/v1/sessions/{public_id}', { params: { path: { public_id: s.public_id } } }));
			if (s.current) {
				// The server ended this session and cleared the cookie; the session store then sends us to log in.
				await session.refresh();
				return true;
			}
			notices.success(s.user.id === session.user?.id ? 'Session ended.' : `${s.user.username}'s session ended.`);
			await onchanged();
			return true;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
			return false;
		} finally {
			busy = null;
		}
	}

	async function confirmEnd(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open until the answer is known
		if (asking && (await revoke(asking))) askOpen = false;
	}

	async function endOthers() {
		for (const s of others) {
			if (!(await revoke(s))) return;
		}
	}
</script>

{#if error}
	<Alert variant="destructive">
		<AlertDescription>{error}</AlertDescription>
	</Alert>
{/if}

{#if rows.length === 0}
	<p class="text-muted-foreground text-sm">No active sessions.</p>
{:else}
	<!-- A list rather than a table: each session has several lines of detail, and it reads better on a phone. -->
	<ul class="divide-y rounded-md border">
		{#each rows as s (s.public_id)}
			<li class="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 p-3">
				<div class="grid min-w-0 gap-1 text-sm">
					<p class="font-medium">
						<!-- One string: Svelte trims whitespace at the edges of an {#if} block, which would eat the spaces. -->
						{mine ? describeAgent(s.user_agent) : `${s.user.username} · ${describeAgent(s.user_agent)}`}
						{#if s.current}<Badge variant="secondary" class="ml-1">This session</Badge>{/if}
						{#if s.user.source === 'ldap' && !mine}<Badge variant="outline" class="ml-1">LDAP</Badge>{/if}
					</p>
					<p class="text-muted-foreground">
						{s.ip || 'Unknown address'} · started {formatDateTime(s.created_at)} · last active {formatDateTime(s.last_seen_at)}
					</p>
					<p class="text-muted-foreground text-xs">Ends by {formatDateTime(s.expires_at)}, or sooner if left idle.</p>
				</div>
				<Button
					variant="outline"
					size="sm"
					disabled={busy === s.public_id}
					onclick={() => end(s)}
					aria-label="End {s.current ? 'this session' : `${s.user.username}'s session from ${describeAgent(s.user_agent)}`}"
				>
					{busy === s.public_id ? 'Ending…' : s.current ? 'Log out' : 'End'}
				</Button>
			</li>
		{/each}
	</ul>
{/if}

<div class="flex flex-wrap gap-2">
	{#if cursor}
		<Button variant="outline" size="sm" onclick={showMore} disabled={loading}>{loading ? 'Reading…' : 'Show more'}</Button>
	{/if}
	{#if mine && others.length > 0}
		<Button variant="outline" size="sm" onclick={endOthers} disabled={busy !== null}>End all your other sessions</Button>
	{/if}
</div>

<AlertDialog.Root bind:open={askOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>
				{asking?.current ? 'Log out of this session?' : `End ${asking?.user.username}'s session?`}
			</AlertDialog.Title>
			<AlertDialog.Description>
				{#if asking?.current}
					You are logged out here at once. Your other sessions carry on.
				{:else}
					{asking?.user.username} is logged out of that browser at once, and can log in again.
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy !== null}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy !== null} onclick={confirmEnd}>
				{asking?.current ? 'Log out' : 'End session'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
