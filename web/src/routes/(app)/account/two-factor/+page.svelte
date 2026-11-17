<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto, invalidate } from '$app/navigation';
	import RecoveryCodes from '#lib/components/app/recovery-codes.svelte';
	import TOTPDisableDialog from '#lib/components/app/totp-disable-dialog.svelte';
	import TOTPRecoveryDialog from '#lib/components/app/totp-recovery-dialog.svelte';
	import TOTPSetup from '#lib/components/app/totp-setup.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { _totpKey as totpKey } from './+page.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	// The recovery codes from turning it on, shown until the user says they have kept them.
	let newCodes = $state<string[] | null>(null);
	// Whether the user was held to this page when they turned it on, so Done can take them into the app.
	let wasHeld = $state(false);
	let disableOpen = $state(false);
	let recoveryOpen = $state(false);

	let status = $derived(data.status);

	async function enabled(codes: string[]) {
		wasHeld = session.held;
		newCodes = codes;
		notices.success('Two-factor login is on. Your other sessions have been logged out.');
		// The session no longer says setup is required, and the page reads the new status.
		await Promise.allSettled([session.refresh(), invalidate(totpKey)]);
	}

	async function done() {
		newCodes = null;
		if (wasHeld) await goto('/');
	}

	async function disabled() {
		notices.success('Two-factor login is off. Your other sessions have been logged out.');
		// If it is required, the session is held again; refresh() stays here, which is where they need to be.
		await Promise.allSettled([session.refresh(), invalidate(totpKey)]);
	}
</script>

<svelte:head>
	<title>Two-factor login · pihole-rbac</title>
</svelte:head>

<h1 class="text-xl font-semibold">Two-factor login</h1>
<p class="text-muted-foreground text-sm">
	After your password, you enter a code from an authenticator app on your phone, so a password alone isn't enough to
	log in as you.
</p>

{#if session.held}
	<Alert>
		<AlertDescription>
			You need to set up two-factor login before you can use the app. It's required for your account.
		</AlertDescription>
	</Alert>
{/if}

{#if data.error}
	<Alert variant="destructive"><AlertDescription>Couldn't load your two-factor login: {data.error}</AlertDescription></Alert>
{:else if status}
	<Card.Root>
		<Card.Content class="grid gap-4">
			{#if newCodes}
				<p class="font-medium">Two-factor login is on. Save your recovery codes.</p>
				<RecoveryCodes codes={newCodes} />
				<Button class="w-fit" onclick={done}>I've saved them</Button>
			{:else if status.enabled}
				<div class="grid gap-1">
					<p class="font-medium">Two-factor login is on.</p>
					{#if status.enabled_at}
						<p class="text-muted-foreground text-sm">Turned on {formatDateTime(status.enabled_at)}.</p>
					{/if}
					<p class="text-sm" class:text-destructive={status.recovery_codes_left <= 2}>
						{status.recovery_codes_left} of 10 recovery codes left.
						{#if status.recovery_codes_left <= 2}Get new ones before you run out.{/if}
					</p>
					{#if status.required}
						<p class="text-muted-foreground text-sm">It's required for your account.</p>
					{/if}
				</div>
				<div class="flex flex-wrap gap-2">
					<Button variant="outline" size="sm" onclick={() => (recoveryOpen = true)}>New recovery codes</Button>
					<Button variant="outline" size="sm" onclick={() => (disableOpen = true)}>Turn off</Button>
				</div>
			{:else if !status.available}
				<p class="text-sm">
					Two-factor login can't be set up here: the app has no master key to keep the secret with. Ask whoever runs the
					app to set PIHOLE_RBAC_MASTER_KEY.
				</p>
			{:else}
				<p class="text-sm">Two-factor login is off.</p>
				<TOTPSetup onenabled={enabled} />
			{/if}
		</Card.Content>
	</Card.Root>

	<TOTPDisableDialog bind:open={disableOpen} required={status.required} ondone={disabled} />
	<TOTPRecoveryDialog bind:open={recoveryOpen} ondone={() => invalidate(totpKey)} />
{/if}
