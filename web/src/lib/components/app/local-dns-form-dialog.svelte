<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { api, unwrap } from '#lib/api/client.js';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Label } from '#lib/components/ui/label/index.js';
	import {
		describe,
		directoryConfirmation,
		ipProblem,
		maxReason,
		nameProblem,
		reasonProblem,
		ttlProblem,
		writable,
		type LocalDNSKind,
		type Row
	} from '#lib/local-dns.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { failureMessage, reportResults } from '#lib/write-report.js';

	// One dialog for adding a record or CNAME and for changing one. A change is sent as the entry's own string (from)
	// and the new fields (to); the server adds the new one and then deletes the old. An entry the app couldn't have
	// written (several names, a comment) can't be changed in place: the dialog offers to replace it with one it can.
	let {
		open = $bindable(false),
		target,
		targetName,
		kind,
		entry = null,
		reasonRequired,
		several,
		localNames = [],
		onsaved
	}: {
		open: boolean;
		target: string;
		targetName: string;
		kind: LocalDNSKind;
		entry?: Row | null;
		reasonRequired: boolean;
		// A mirrored group, whose CNAME changes go one member at a time.
		several: boolean;
		// The names the target already answers for itself (its records' hostnames and CNAMEs' aliases), lowercased.
		localNames?: string[];
		onsaved: () => Promise<void> | void;
	} = $props();

	let name = $state('');
	let points = $state('');
	let ttl = $state('');
	let reason = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let touched = $state(false);
	// Set when the server asked to confirm a name under a directory domain; the next save sends confirm=true.
	let confirm = $state<{ domain: string } | null>(null);

	// Filled each time the dialog opens. It reads only open and entry, so typing doesn't reset the fields.
	$effect(() => {
		if (!open) return;
		name = entry?.name ?? '';
		points = entry?.points ?? '';
		ttl = entry?.ttl !== undefined ? String(entry.ttl) : '';
		reason = '';
		error = null;
		touched = false;
		confirm = null;
	});

	let isRecord = $derived(kind === 'record');
	let replacing = $derived(entry !== null && !writable(entry));
	let nameHint = $derived(nameProblem(name));
	let pointsHint = $derived(isRecord ? ipProblem(points) : nameProblem(points));
	let sameName = $derived(!isRecord && name.trim() !== '' && name.trim().toLowerCase() === points.trim().toLowerCase());
	let ttlHint = $derived(isRecord ? null : ttlProblem(ttl));
	// Pi-hole answers a CNAME with an address only when the target is one of its own names; otherwise the answer is
	// the CNAME alone, which many devices don't follow up. Worth a warning, not a refusal.
	let notLocal = $derived(!isRecord && !pointsHint && !localNames.includes(points.trim().toLowerCase()));
	let reasonHint = $derived(reasonProblem(reason, reasonRequired));
	let ready = $derived(!nameHint && !pointsHint && !sameName && !ttlHint && !reasonHint);

	let title = $derived.by(() => {
		const what = isRecord ? 'record' : 'CNAME';
		if (!entry) return `Add a ${what}`;
		return replacing ? `Replace ${what}` : `Change ${what}`;
	});

	async function save(event: SubmitEvent) {
		event.preventDefault();
		touched = true;
		if (!ready) return;
		busy = true;
		error = null;
		const query = (members?: number[]) => ({
			...(members ? { members } : {}),
			...(confirm ? { confirm: true } : {})
		});
		const why = reason.trim() === '' ? undefined : reason.trim();
		const record = { ip: points.trim(), hostname: name.trim() };
		const cname = { alias: name.trim(), target: points.trim(), ...(ttl.trim() !== '' ? { ttl: Number(ttl) } : {}) };
		const shown = describe({ kind, name: name.trim(), points: points.trim(), ttl: ttl.trim() !== '' ? Number(ttl) : undefined });
		const records = '/api/v1/targets/{target}/local-dns/records';
		const cnames = '/api/v1/targets/{target}/local-dns/cnames';
		// One call per path and method, so each body is checked against its own schema.
		const send = async (members?: number[]) => {
			const params = { path: { target }, query: query(members) };
			const from = entry ? { value: entry.value } : null;
			if (isRecord) {
				return from
					? (await unwrap(api.PATCH(records, { params, body: { from, to: record, reason: why } }))).results
					: (await unwrap(api.POST(records, { params, body: { ...record, reason: why } }))).results;
			}
			return from
				? (await unwrap(api.PATCH(cnames, { params, body: { from, to: cname, reason: why } }))).results
				: (await unwrap(api.POST(cnames, { params, body: { ...cname, reason: why } }))).results;
		};
		try {
			const results = await send();
			reportResults(
				results,
				{ done: entry ? `${shown} saved` : `${shown} added`, failed: `Couldn't save ${shown}` },
				{ retry: send, after: onsaved }
			);
			const pending = results.filter((r) => r.restart_pending).map((r) => r.instance);
			if (pending.length > 0) {
				notices.info(`${pending.join(', ')} hadn't answered again after restarting DNS. Check that it's running.`);
			}
			open = false;
			await onsaved();
		} catch (e) {
			const c = directoryConfirmation(e);
			if (c) confirm = { domain: c.domain };
			else error = failureMessage(e);
		} finally {
			busy = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>{title}</Dialog.Title>
			<Dialog.Description>
				{#if replacing && entry}
					<span class="font-mono break-all">{entry.value}</span> was added outside the app with
					{entry.marks.includes('comment') ? 'a comment' : 'several names'}, which the app doesn't write. Saving adds
					the entry below and deletes that one.
				{:else if entry}
					A change adds the new {isRecord ? 'record' : 'CNAME'} on {targetName}, then deletes the old one.
				{:else if isRecord}
					A name {targetName} answers with an address of your choosing, before asking any upstream server.
				{:else}
					Another name for a name {targetName} already answers for.
				{/if}
			</Dialog.Description>
		</Dialog.Header>

		<form id="local-dns-form" class="grid gap-4" onsubmit={save} oninput={() => (touched = true)}>
			{#if error}
				<Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
			{/if}
			{#if confirm}
				<Alert>
					<AlertDescription>
						{name.trim()} is in the directory's domain {confirm.domain}. A local record there answers before the
						directory's own DNS, and can hide a real name. Save anyway only if that is what you mean.
					</AlertDescription>
				</Alert>
			{/if}

			<div class="grid gap-2">
				<Label for="local-dns-name">{isRecord ? 'Hostname' : 'Alias'}</Label>
				<Input
					id="local-dns-name"
					bind:value={name}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder={isRecord ? 'nas.lab' : 'files.lab'}
					aria-invalid={touched && nameHint !== null}
					aria-describedby="local-dns-name-hint"
					oninput={() => (confirm = null)}
				/>
				{#if touched && nameHint}<p id="local-dns-name-hint" class="text-destructive text-sm">{nameHint}</p>{/if}
			</div>

			<div class="grid gap-2">
				<Label for="local-dns-points">{isRecord ? 'Address' : 'Target'}</Label>
				<Input
					id="local-dns-points"
					bind:value={points}
					class="font-mono"
					autocomplete="off"
					spellcheck={false}
					placeholder={isRecord ? '10.0.0.5' : 'nas.lab'}
					aria-invalid={touched && (pointsHint !== null || sameName)}
					aria-describedby="local-dns-points-hint"
				/>
				<p
					id="local-dns-points-hint"
					class={touched && (pointsHint || sameName) ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}
				>
					{#if touched && pointsHint}{pointsHint}{:else if touched && sameName}The target can't be the alias itself.{:else if isRecord}IPv4
						or IPv6.{:else}The name the alias stands for, usually one of this Pi-hole's own records.{/if}
				</p>
			</div>

			{#if notLocal}
				<Alert>
					<AlertDescription>
						{points.trim()} isn't one of {targetName}'s own records. Pi-hole then answers {name.trim() || 'the alias'} with
						the CNAME alone, without an address, and many devices won't look {points.trim()} up themselves. Add a record
						for it first, or point the alias at a name {targetName} already has.
					</AlertDescription>
				</Alert>
			{/if}

			{#if !isRecord}
				<div class="grid gap-2">
					<Label for="local-dns-ttl">TTL (seconds)</Label>
					<Input
						id="local-dns-ttl"
						bind:value={ttl}
						class="w-32"
						inputmode="numeric"
						autocomplete="off"
						placeholder="Default"
						aria-invalid={touched && ttlHint !== null}
						aria-describedby="local-dns-ttl-hint"
					/>
					<p id="local-dns-ttl-hint" class={touched && ttlHint ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}>
						{touched && ttlHint ? ttlHint : "Leave empty for Pi-hole's default."}
					</p>
				</div>
			{/if}

			<div class="grid gap-2">
				<Label for="local-dns-reason">Reason{reasonRequired ? '' : ' (optional)'}</Label>
				<Input
					id="local-dns-reason"
					bind:value={reason}
					autocomplete="off"
					maxlength={maxReason}
					aria-invalid={touched && reasonHint !== null}
					aria-describedby="local-dns-reason-hint"
				/>
				<p id="local-dns-reason-hint" class={touched && reasonHint ? 'text-destructive text-sm' : 'text-muted-foreground text-xs'}>
					{touched && reasonHint ? reasonHint : 'Kept in the audit log and shown beside the entry.'}
				</p>
			</div>

			{#if !isRecord}
				<p class="text-muted-foreground text-sm">
					Saving restarts DNS on {several
						? 'each member of ' + targetName + ', one at a time,'
						: targetName}, so it doesn't answer for a moment.
				</p>
			{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={busy}>Cancel</Button>
			<Button type="submit" form="local-dns-form" disabled={busy || (touched && !ready)}>
				{#if busy}Saving…{:else if confirm}Save anyway{:else if entry}Save{:else}Add{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
