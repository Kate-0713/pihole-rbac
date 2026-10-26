<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import UpdateHistory from '#lib/components/app/update-history.svelte';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { whileVisible } from '#lib/poll.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { updates } from '#lib/stores/updates.svelte.js';
	import {
		activeRequest,
		displayVersion,
		dockerCommands,
		finishedOutcome,
		requestTarget,
		targetProblem,
		type UpdateStatus
	} from '#lib/system.js';

	// Updates: the latest release, Update now on an LXC install (carried out by the root updater service), the
	// commands to run on Docker, and the latest requests with their logs. While a request is pending or running the
	// card asks for the status every two seconds; the app restarts part-way, so failed asks then are expected.
	let { initial }: { initial: UpdateStatus } = $props();

	// The status as last read. It starts from the page's load and is then kept by this card, which is why `initial` is
	// read only once here (Svelte warns about reading a prop outside a reactive context; here that is the point).
	// svelte-ignore state_referenced_locally
	let status = $state<UpdateStatus>(initial);
	// The version the page was loaded with: when it changes, the browser is still running the old version's pages.
	// svelte-ignore state_referenced_locally
	const loadedVersion = initial.current_version;

	// $effect runs after the component is on the page and again whenever what it reads changes. This one keeps the
	// shared store (and so the banner) in step with the card.
	$effect(() => {
		updates.set(status);
	});

	let active = $derived(activeRequest(status));
	let running = $derived(displayVersion(status.current_version, status.development));
	let restarting = $state(false);

	// While the updater restarts the app, the server doesn't answer, or a reverse proxy in front answers 502 to 504.
	const restartingError = (e: unknown) =>
		e instanceof ApiError && (e.code === 'network_error' || [502, 503, 504].includes(e.status));

	async function refresh() {
		let next: UpdateStatus;
		try {
			next = await unwrap(api.GET('/api/v1/system/update'));
		} catch (e) {
			if (restartingError(e)) restarting = true; // keep asking
			else notices.error(e, "Couldn't read the update status");
			return;
		}
		restarting = false;
		const outcome = finishedOutcome(status, next);
		status = next;
		if (outcome?.ok) notices.success(outcome.message);
		else if (outcome) notices.error(outcome.message);
	}

	// Only while a request is pending or running. The function returned by whileVisible stops the polling when the
	// effect re-runs (the request finished) or the card goes away.
	$effect(() => {
		if (!active) return;
		return whileVisible(refresh, 2000);
	});

	let checking = $state(false);
	async function checkNow() {
		checking = true;
		try {
			status = await unwrap(api.POST('/api/v1/system/update/check'));
			if (status.check_error) notices.error(status.check_error, "The check didn't reach GitHub");
			else if (!status.update_available) notices.success('No newer release.');
		} catch (e) {
			notices.error(e, "Couldn't check for a new release");
		} finally {
			checking = false;
		}
	}

	let target = $state('');
	let problem = $derived(targetProblem(target));
	let confirmOpen = $state(false);
	let requesting = $state(false);
	let describedTarget = $derived(target.trim() || (status.latest?.version ?? 'the latest release'));

	function askToUpdate(event: SubmitEvent) {
		event.preventDefault();
		if (!problem) confirmOpen = true;
	}

	async function requestUpdate(event: MouseEvent) {
		event.preventDefault(); // keep the dialog open while the request is sent
		requesting = true;
		try {
			const t = target.trim();
			await unwrap(api.POST('/api/v1/system/update', { body: t ? { target_version: t } : {} }));
			notices.info('Update requested. Progress is shown below.');
			target = '';
			await refresh();
		} catch (e) {
			notices.error(e, "Couldn't request the update");
		} finally {
			requesting = false;
			confirmOpen = false;
		}
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Updates</h2></Card.Title>
		<Card.Description>
			{#if status.install === 'lxc'}
				Updates are carried out by the updater service, which checks the release's signature, backs up the
				database, and puts the previous version back if the new one doesn't start.
			{:else if status.install === 'docker'}
				In Docker the app never updates itself: pull the new image on the Docker host.
			{:else}
				Install a new release the same way this one was installed.
			{/if}
		</Card.Description>
	</Card.Header>
	<Card.Content class="grid gap-4">
		<div class="grid gap-1 text-sm" aria-live="polite">
			{#if status.update_available && status.latest}
				<p>
					<strong>{status.latest.version}</strong> is available; this is {running}.
					<a class="underline" href={status.latest.url} target="_blank" rel="noopener noreferrer">What's new</a>
				</p>
			{:else if status.latest && !status.development}
				<p>No newer release: this is {running}, and the latest release is {status.latest.version}.</p>
			{:else if status.latest}
				<p>
					The latest release is <a class="underline" href={status.latest.url} target="_blank" rel="noopener noreferrer"
						>{status.latest.version}</a
					>. This development build ({running}) can't be compared with it.
				</p>
			{:else if status.check_enabled && status.checked_at && !status.check_error}
				<p>No release has been published yet.</p>
			{/if}
			{#if !status.check_enabled}
				<p class="text-muted-foreground">
					The update check is off (<code>PIHOLE_RBAC_UPDATE_CHECK=false</code>), so new releases aren't looked for.
				</p>
			{:else}
				<p class="text-muted-foreground">
					{status.checked_at ? `Last checked ${formatDateTime(status.checked_at)}.` : 'Not checked yet.'} The app checks
					once a day.
				</p>
			{/if}
		</div>
		{#if status.check_error}
			<Alert variant="destructive"><AlertDescription>The last check failed: {status.check_error}</AlertDescription></Alert>
		{/if}

		{#if restarting}
			<Alert><AlertDescription>The app is restarting. This page carries on once it answers again.</AlertDescription></Alert>
		{/if}
		{#if status.current_version !== loadedVersion}
			<Alert>
				<AlertDescription class="flex flex-wrap items-center gap-3">
					<span>The server now runs {running}. Reload the page to use its version of these pages.</span>
					<Button size="sm" variant="outline" onclick={() => location.reload()}>Reload</Button>
				</AlertDescription>
			</Alert>
		{/if}

		{#if status.install === 'lxc'}
			{#if active}
				<p class="text-sm">Updating to {requestTarget(active)}. You can leave this page; the update carries on.</p>
			{:else if status.development}
				<p class="text-muted-foreground text-sm">
					This is a development build, so it can't be updated from here. Install a release with install.sh.
				</p>
			{:else if status.can_request}
				<form id="update-form" class="grid gap-2" onsubmit={askToUpdate}>
					<Label for="update-target">Version (optional)</Label>
					<Input
						id="update-target"
						bind:value={target}
						placeholder="Latest release"
						class="w-56"
						autocomplete="off"
						aria-invalid={problem !== null}
						aria-describedby="update-target-hint"
					/>
					<p id="update-target-hint" class={problem ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
						{problem ?? 'Leave empty for the latest release, or give a newer tag such as v2.1.0-rc.1 to try a prerelease.'}
					</p>
				</form>
			{/if}
		{:else if status.install === 'docker'}
			<div class="grid gap-1 text-sm">
				<p>On the Docker host, in the folder with the compose file:</p>
				<pre class="bg-muted rounded p-2 text-xs">{dockerCommands.join('\n')}</pre>
				<p class="text-muted-foreground">The database is backed up and migrated when the new container starts.</p>
			</div>
		{/if}

		<UpdateHistory requests={status.requests} />
	</Card.Content>
	<Card.Footer class="flex flex-wrap items-center gap-3">
		{#if status.install === 'lxc' && status.can_request && !active}
			<Button type="submit" form="update-form" disabled={problem !== null}>Update now</Button>
		{/if}
		{#if status.check_enabled}
			<Button variant="outline" onclick={checkNow} disabled={checking}>
				{checking ? 'Checking…' : 'Check now'}
			</Button>
		{/if}
	</Card.Footer>
</Card.Root>

<AlertDialog.Root bind:open={confirmOpen}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Update to {describedTarget}?</AlertDialog.Title>
			<AlertDialog.Description>
				The app restarts during the update, which takes about a minute: everyone's pages stop answering for a few
				seconds, and changes made while it runs may be lost if the update is rolled back. Sessions are kept.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={requesting}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'default' })} disabled={requesting} onclick={requestUpdate}>
				{requesting ? 'Requesting…' : 'Update now'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
