<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { recoveryCodesFile } from '#lib/totp.js';

	// Shows a new set of recovery codes, once: the server keeps only their hashes. Copy and Download are the two ways
	// to keep them; the codes are plain text on the page as well, for printing or writing down.
	let { codes }: { codes: string[] } = $props();

	let copied = $state(false);
	let copyFailed = $state(false);

	let text = $derived(recoveryCodesFile(codes, session.user?.username ?? '', new Date(), window.location.host));

	async function copy() {
		copyFailed = false;
		try {
			// The clipboard API needs a secure context (HTTPS or localhost), so it can fail on plain HTTP.
			await navigator.clipboard.writeText(codes.join('\n'));
			copied = true;
		} catch {
			copyFailed = true;
		}
	}

	function download() {
		// A Blob made here and saved through a temporary link: nothing leaves the browser, and no request is made.
		const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
		const a = document.createElement('a');
		a.href = url;
		a.download = `pihole-rbac-recovery-codes-${session.user?.username ?? 'account'}.txt`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<section aria-label="Recovery codes" class="grid gap-3">
	<p class="text-sm">
		Keep these somewhere safe, away from your phone. Each one logs you in once if you can't use your authenticator app.
		They won't be shown again.
	</p>
	<ul class="bg-muted grid grid-cols-2 gap-x-6 gap-y-1 rounded-md p-3 font-mono text-sm">
		{#each codes as code (code)}
			<li>{code}</li>
		{/each}
	</ul>
	<div class="flex flex-wrap gap-2">
		<Button variant="outline" size="sm" onclick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
		<Button variant="outline" size="sm" onclick={download}>Download</Button>
	</div>
	{#if copyFailed}
		<p class="text-destructive text-sm">Couldn't copy here (the browser only allows it over HTTPS). Use Download instead.</p>
	{/if}
</section>
