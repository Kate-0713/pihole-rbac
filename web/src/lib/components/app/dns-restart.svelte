<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { reportFailure, reportResults } from '#lib/write-report.js';

	let { target, name, onchange }: { target: string; name: string; onchange: () => Promise<void> | void } = $props();

	// Restarting drops DNS for everyone on the network for a moment, so it asks first: the button turns into a
	// confirmation in place, rather than opening a dialog.
	let confirming = $state(false);
	let busy = $state(false);

	async function restart() {
		busy = true;
		const text = { done: 'DNS restarted', failed: "Couldn't restart DNS" };
		// For a mirrored group, a retry restarts only the members that failed, named in ?members=.
		const send = async (members?: number[]) => {
			const query = members ? { members } : undefined;
			const { results } = await unwrap(
				api.POST('/api/v1/targets/{target}/dns/restart', { params: { path: { target }, query } })
			);
			return results;
		};
		const retry = { retry: send, after: onchange };
		try {
			const results = await send();
			if (results.every((r) => r.status !== 'ok' || r.confirmed)) {
				reportResults(results, text, retry);
			} else {
				// The restart took the connection down with it before Pi-hole could answer. That usually means it worked.
				reportResults(results, { ...text, done: 'DNS restart requested' }, retry);
				notices.info("Pi-hole didn't confirm the restart before the connection dropped. Check back in a few seconds.");
			}
		} catch (e) {
			reportFailure(e, text, retry);
		} finally {
			confirming = false;
			busy = false;
			await onchange();
		}
	}
</script>

{#if confirming}
	<div class="flex flex-wrap items-center gap-2" role="group" aria-label="Confirm DNS restart">
		<span class="text-sm">Restart DNS on {name}? Lookups fail for a moment while it restarts.</span>
		<Button size="sm" variant="destructive" disabled={busy} onclick={restart}>
			{busy ? 'Restarting…' : 'Restart now'}
		</Button>
		<Button size="sm" variant="ghost" disabled={busy} onclick={() => (confirming = false)}>Cancel</Button>
	</div>
{:else}
	<Button size="sm" variant="outline" class="w-fit" onclick={() => (confirming = true)}>Restart DNS…</Button>
{/if}
