<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import type { UpdateStatus } from '#lib/system.js';

	// Restarts the app, as v1's restart did: the server shuts down cleanly and systemd or Docker starts it again.
	// Afterwards the card asks the server until it answers. `install` decides the warning about who restarts it.
	let {
		install,
		onrestarted,
		// How long to wait before the first ask, between asks, and in all. Tests make them short.
		timing = { first: 2000, every: 1000, limit: 90_000 }
	}: {
		install: UpdateStatus['install'] | null;
		onrestarted: () => Promise<void> | void;
		timing?: { first: number; every: number; limit: number };
	} = $props();

	let open = $state(false);
	let phase = $state<'idle' | 'sending' | 'waiting' | 'gone'>('idle');

	const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

	async function restart(event: MouseEvent) {
		event.preventDefault();
		phase = 'sending';
		try {
			await unwrap(api.POST('/api/v1/system/restart'));
		} catch (e) {
			notices.error(e, "Couldn't restart the app");
			phase = 'idle';
			open = false;
			return;
		}
		open = false;
		phase = 'waiting';
		// The server stops listening as soon as it starts shutting down, so an answer after the first wait comes from
		// the new process.
		await sleep(timing.first);
		const deadline = Date.now() + timing.limit;
		while (Date.now() < deadline) {
			try {
				await unwrap(api.GET('/api/v1/system/version'));
				phase = 'idle';
				notices.success('pihole-rbac has restarted.');
				await onrestarted();
				return;
			} catch {
				await sleep(timing.every);
			}
		}
		phase = 'gone';
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Restart</h2></Card.Title>
		<Card.Description>
			Restarts the app: requests in progress finish, every Pi-hole session is logged out, and the service manager
			starts it again. Sessions are kept.
		</Card.Description>
	</Card.Header>
	<Card.Content class="grid gap-2" aria-live="polite">
		{#if phase === 'waiting'}
			<Alert><AlertDescription>Restarting… waiting for the app to answer again.</AlertDescription></Alert>
		{:else if phase === 'gone'}
			<Alert variant="destructive">
				<AlertDescription>
					The app hasn't come back after {Math.round(timing.limit / 1000)} seconds. Check its service
					(journalctl -u pihole-rbac, or docker compose logs).
				</AlertDescription>
			</Alert>
		{/if}
	</Card.Content>
	<Card.Footer>
		<Button variant="outline" onclick={() => (open = true)} disabled={phase !== 'idle' && phase !== 'gone'}>
			Restart the app
		</Button>
	</Card.Footer>
</Card.Root>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Restart pihole-rbac?</AlertDialog.Title>
			<AlertDialog.Description>
				Everyone's pages stop answering for a few seconds.
				{#if install !== 'lxc' && install !== 'docker'}
					This server doesn't say it runs under systemd or Docker: if nothing restarts it, it stays stopped until
					it is started by hand.
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={phase === 'sending'}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action
				class={buttonVariants({ variant: 'destructive' })}
				disabled={phase === 'sending'}
				onclick={restart}
			>
				{phase === 'sending' ? 'Restarting…' : 'Restart'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
