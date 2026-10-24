<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { ApiError, api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { formatDateTime } from '#lib/format.js';
	import { formProblems, needsPassword, passwordStatus, plainLDAP, toForm, type LDAPView } from '#lib/ldap.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// The LDAP server settings and the bind password. The password is write-only: the field starts empty, and an empty
	// field keeps the one already set. The server asks for it again before sending it to a new server; the form says
	// so before it is asked.
	let { view, onsaved }: { view: LDAPView; onsaved: () => Promise<void> | void } = $props();

	let form = $state(toForm(undefined));
	let password = $state('');
	$effect(() => {
		form = toForm(view.settings);
		password = '';
	});

	let busy = $state(false);
	let touched = $state(false);
	let error = $state<{ message: string; detail?: string; field?: string } | null>(null);

	let hints = $derived(formProblems(form));
	let ready = $derived(Object.values(hints).every((h) => h === null));
	let wantPassword = $derived(needsPassword(view, form) && password === '');
	// Without a master key a password can't be stored; one from the environment can still be confirmed.
	let canEnterPassword = $derived(view.can_store_password || view.bind_password.source === 'environment');

	const tlsLabel = { verify: 'Verify the certificate', insecure: "Don't verify (labs only)" } as const;

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		if (wantPassword) {
			error = {
				message: 'Enter the bind password again: a saved password is only sent to the server it was entered for.',
				field: 'bind_password'
			};
			return;
		}
		busy = true;
		error = null;
		try {
			await unwrap(
				api.PUT('/api/v1/settings/ldap', {
					body: {
						url: form.url.trim(),
						bind_dn: form.bind_dn.trim(),
						base_dn: form.base_dn.trim(),
						user_filter: form.user_filter.trim(),
						tls_mode: form.tls_mode,
						allow_cn_fallback: form.allow_cn_fallback,
						...(password !== '' ? { bind_password: password } : {})
					}
				})
			);
			notices.success('LDAP settings saved.');
			await onsaved();
		} catch (e) {
			if (e instanceof ApiError) {
				error = {
					message: e.message,
					detail: typeof e.details.detail === 'string' ? e.details.detail : undefined,
					field: typeof e.details.field === 'string' ? e.details.field : undefined
				};
			} else {
				error = { message: 'Something went wrong. Try again.' };
			}
		} finally {
			busy = false;
		}
	}

	const invalid = (field: keyof typeof hints) => touched && hints[field] !== null;
</script>

{#snippet field(id: keyof typeof hints, label: string, placeholder: string, mono = true)}
	<div class="grid gap-2">
		<Label for="ldap-{id}">{label}</Label>
		<Input
			id="ldap-{id}"
			bind:value={form[id]}
			{placeholder}
			autocomplete="off"
			spellcheck={false}
			class={mono ? 'font-mono' : ''}
			aria-invalid={invalid(id) || error?.field === id}
			aria-describedby="ldap-{id}-hint"
		/>
		{#if invalid(id)}
			<p id="ldap-{id}-hint" class="text-destructive text-sm">{hints[id]}</p>
		{/if}
	</div>
{/snippet}

<Card.Root>
	<Card.Header>
		<Card.Title><h2>LDAP server</h2></Card.Title>
		<Card.Description>
			{#if view.enabled}
				LDAP login is on, so saving tests a bind with the new settings first, and keeps the old ones if it fails.
			{:else}
				The service account that finds users and their groups. LDAP login is off, so nothing is tested until it is
				turned on.
			{/if}
		</Card.Description>
	</Card.Header>
	<Card.Content>
		<form id="ldap-settings-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive">
					<AlertDescription>
						<p>{error.message}</p>
						{#if error.detail}<p class="font-mono text-xs break-all">{error.detail}</p>{/if}
					</AlertDescription>
				</Alert>
			{/if}
			<!-- {@render} draws a snippet declared above: Svelte 5's way to reuse a piece of markup within one component. -->
			{@render field('url', 'Server URL', 'ldaps://dc01.example.com')}
			{#if plainLDAP(form.url)}
				<p class="text-sm text-amber-700 dark:text-amber-400">
					ldap:// isn't encrypted, so passwords cross the network in the clear. Use ldaps:// if the server supports it.
				</p>
			{/if}
			{@render field('bind_dn', 'Bind DN', 'cn=svc-pihole,ou=service,dc=example,dc=com')}
			<div class="grid gap-2">
				<Label for="ldap-bind-password">Bind password</Label>
				<Input
					id="ldap-bind-password"
					type="password"
					bind:value={password}
					autocomplete="new-password"
					disabled={!canEnterPassword}
					aria-invalid={error?.field === 'bind_password' || (touched && wantPassword)}
					aria-describedby="ldap-bind-password-hint"
				/>
				<p
					id="ldap-bind-password-hint"
					class="text-sm"
					class:text-destructive={touched && wantPassword}
					class:text-muted-foreground={!(touched && wantPassword)}
				>
					{#if !canEnterPassword}
						A password can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Set
						{view.bind_password.variable} instead.
					{:else if needsPassword(view, form)}
						Enter the bind password again: it's only sent to the server it was entered for.
					{:else}
						{passwordStatus(view)}
					{/if}
				</p>
			</div>
			{@render field('base_dn', 'Base DN', 'dc=example,dc=com')}
			{@render field('user_filter', 'User filter', '(uid=%s)')}
			<div class="grid gap-2 sm:max-w-xs">
				<Label for="ldap-tls">Certificate</Label>
				<Select.Root type="single" bind:value={form.tls_mode}>
					<Select.Trigger id="ldap-tls" class="w-full">{tlsLabel[form.tls_mode]}</Select.Trigger>
					<Select.Content>
						<Select.Item value="verify" label={tlsLabel.verify}>{tlsLabel.verify}</Select.Item>
						<Select.Item value="insecure" label={tlsLabel.insecure}>{tlsLabel.insecure}</Select.Item>
					</Select.Content>
				</Select.Root>
			</div>
			{#if form.tls_mode === 'verify'}
				<div class="flex items-start gap-2">
					<Checkbox id="ldap-cn" bind:checked={form.allow_cn_fallback} class="mt-0.5" aria-describedby="ldap-cn-note" />
					<div class="grid gap-0.5">
						<Label for="ldap-cn" class="font-normal">Accept a certificate that names the host only in its Common Name</Label>
						<p id="ldap-cn-note" class="text-muted-foreground text-xs">
							For older internal CAs. {view.ca_file_set
								? 'Applies to certificates from PIHOLE_RBAC_LDAP_CA_FILE.'
								: "Only applies with PIHOLE_RBAC_LDAP_CA_FILE, which isn't set."}
						</p>
					</div>
				</div>
			{/if}
		</form>
	</Card.Content>
	<Card.Footer class="flex flex-wrap items-center gap-3">
		<Button type="submit" form="ldap-settings-form" disabled={busy || (touched && !ready)}>
			{#if busy}{view.enabled ? 'Testing…' : 'Saving…'}{:else}Save LDAP settings{/if}
		</Button>
		{#if view.updated_at}
			<p class="text-muted-foreground text-xs">
				Last saved {formatDateTime(view.updated_at)}{view.updated_by ? ` by ${view.updated_by}` : ''}.
			</p>
		{/if}
	</Card.Footer>
</Card.Root>
