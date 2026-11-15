<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { buttonVariants } from '#lib/components/ui/button/index.js';
	import type { Schedule } from '#lib/schedules.js';
	import { notices } from '#lib/stores/notices.svelte.js';

	// Deleting a schedule changes nothing on the Pi-holes: a blocking window's timer runs on, and a group stays as it is.
	let {
		open = $bindable(false),
		target,
		schedule,
		ondeleted
	}: { open: boolean; target: string; schedule: Schedule | null; ondeleted: () => Promise<void> | void } = $props();

	let busy = $state(false);

	async function remove(event: MouseEvent) {
		event.preventDefault();
		if (!schedule) return;
		busy = true;
		try {
			await unwrap(api.DELETE('/api/v1/targets/{target}/schedules/{id}', { params: { path: { target, id: schedule.id } } }));
			notices.success(`Schedule ${schedule.name} deleted.`);
		} catch (e) {
			notices.error(e, `Couldn't delete ${schedule.name}`);
		} finally {
			busy = false;
			open = false;
			await ondeleted();
		}
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Delete {schedule?.name ?? 'this schedule'}?</AlertDialog.Title>
			<AlertDialog.Description>
				{#if schedule?.open}
					Its window is open now. Deleting it doesn't put anything back:
					{schedule.kind === 'blocking_off'
						? "blocking comes back on when Pi-hole's timer runs out"
						: `${schedule.pihole_group} stays as it is until someone changes it`}.
				{:else}
					It won't act again. Nothing on the Pi-holes changes.
				{/if}
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action class={buttonVariants({ variant: 'destructive' })} disabled={busy} onclick={remove}>
				{busy ? 'Deleting…' : 'Delete'}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
