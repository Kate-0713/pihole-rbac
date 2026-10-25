// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The notifications page's helpers: browser-side copies of the server's rules for a channel (Input.normalize in
// internal/notifications and the URL rules in internal/notify), so the form can say what's wrong before it is sent,
// and the summaries the page shows. The server checks everything again.
import type { Schemas } from '#lib/api/client.js';
import { formatDateTime } from '#lib/format.js';
import { controlChars } from '#lib/pihole.js';

export type Channel = Schemas['Channel'];
export type ChannelInput = Schemas['ChannelInput'];
export type ChannelKind = Channel['kind'];
export type NotificationEvent = Schemas['NotificationEvent'];

export const maxNameChars = 64;
export const maxEnvNameChars = 64;
export const maxSecretChars = 2048;

export const kindLabel: Record<ChannelKind, string> = { discord: 'Discord', matrix: 'Matrix' };

// secretWord names a kind's secret.
export function secretWord(kind: ChannelKind): string {
	return kind === 'discord' ? 'webhook URL' : 'access token';
}

// secretVariable is the variable whose secret overrides a channel's stored one, as secrets.ChannelVar builds it.
export function secretVariable(envName: string): string {
	return `PIHOLE_RBAC_NOTIFY_${envName || '<ENV_NAME>'}_SECRET`;
}

export function nameProblem(name: string): string | null {
	const n = [...name.trim()].length;
	if (n === 0 || n > maxNameChars || controlChars.test(name.trim())) {
		return `A name is 1-${maxNameChars} characters, with no control characters.`;
	}
	return null;
}

export function envNameProblem(envName: string): string | null {
	const e = envName.trim();
	if (e.length > maxEnvNameChars || !/^[A-Z0-9_]*$/.test(e)) {
		return `Leave it empty, or use up to ${maxEnvNameChars} characters of A-Z, 0-9 and _.`;
	}
	return null;
}

const webhookPattern = /^https:\/\/(discord\.com|discordapp\.com)(:443)?\/api\/webhooks\/[0-9]{1,20}\/[A-Za-z0-9_-]{1,100}$/i;

// webhookProblem follows notify.ParseDiscordWebhook: only Discord's own hosts, so a channel can't be pointed at the
// local network.
export function webhookProblem(url: string): string | null {
	const u = url.trim();
	if (u === '') return 'Paste the webhook URL.';
	if (u.length > maxSecretChars) return 'That webhook URL is too long.';
	if (!webhookPattern.test(u)) {
		return 'Use a Discord webhook URL: https://discord.com/api/webhooks/<id>/<token>, from the channel’s Integrations settings.';
	}
	return null;
}

// homeserverProblem follows MatrixConfig.Normalize. A homeserver may be on the local network; plain HTTP needs
// allowHTTP.
export function homeserverProblem(homeserver: string, allowHTTP: boolean): string | null {
	const h = homeserver.trim();
	if (h === '') return "Give the homeserver's URL.";
	let u: URL;
	try {
		u = new URL(h);
	} catch {
		return "That isn't a URL.";
	}
	if (u.protocol === 'http:' && !allowHTTP) return 'Use https://, or allow plain HTTP below.';
	if (u.protocol !== 'https:' && u.protocol !== 'http:') return 'The URL starts with https:// (or http://).';
	if (u.username || u.password || u.search || u.hash || h.includes('#')) return 'A homeserver URL has no username, query or fragment.';
	return null;
}

export function roomProblem(room: string): string | null {
	const r = room.trim();
	if (r.length > 255 || !/^![A-Za-z0-9._=/+-]+:[A-Za-z0-9.-]+(:[0-9]{1,5})?$/.test(r)) {
		return 'Use the room’s internal ID, like !abcdefg:example.org (in most clients: Room settings → Advanced). Not an alias starting with #.';
	}
	return null;
}

export function tokenProblem(token: string): string | null {
	if (token === '') return 'Paste the access token.';
	if (token.length > 1024) return 'That access token is too long.';
	if (!/^[!-~]+$/.test(token)) return 'An access token has no spaces or special characters.';
	return null;
}

// secretProblem checks a secret for its kind.
export function secretProblem(kind: ChannelKind, secret: string): string | null {
	return kind === 'discord' ? webhookProblem(secret) : tokenProblem(secret);
}

// normalizeHomeserver is the form of a homeserver the server keeps: lower-case scheme and host, no trailing slash.
// It's only used to tell whether the homeserver changed.
export function normalizeHomeserver(h: string): string {
	try {
		const u = new URL(h.trim());
		return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
	} catch {
		return h.trim();
	}
}

// What the form would save, for the rules below.
export type ChannelForm = { homeserver: string; allowHTTP: boolean; enabled: boolean; events: string[]; secret: string };

// needsSecret follows the server's confirmation rule for a Matrix channel: a token goes only to the homeserver it was
// entered for, so a new homeserver, or allowing or forbidding plain HTTP, needs the token again. (A channel starting
// to use a set variable needs it too, but only the server knows whether the variable is set: the form asks when it
// says so.)
export function needsSecret(channel: Channel | null, f: ChannelForm): boolean {
	if (!channel || channel.kind !== 'matrix' || channel.secret_source === 'none' || !channel.matrix) return false;
	return (
		normalizeHomeserver(f.homeserver) !== channel.matrix.homeserver ||
		f.allowHTTP !== (channel.matrix.allow_http ?? false)
	);
}

// guardWarnings says what the channel's current destination will be told when the form is saved, as the server's
// guards decide (internal/notifications Update): a new destination or secret, the channel disabled, or events taken
// away while it stays enabled. Nothing is sent where there is no secret yet.
export function guardWarnings(channel: Channel | null, f: ChannelForm): string[] {
	if (!channel || channel.secret_source === 'none' || channel.secret_problem) return [];
	const out: string[] = [];
	const homeserverChanged =
		channel.kind === 'matrix' && channel.matrix !== undefined && normalizeHomeserver(f.homeserver) !== channel.matrix.homeserver;
	if (f.secret !== '' || homeserverChanged) out.push('it now sends somewhere else');
	if (channel.enabled && !f.enabled) {
		out.push('it was disabled');
	} else if (channel.enabled && f.enabled) {
		const removed = channel.events.filter((e) => !f.events.includes(e));
		if (removed.length > 0) out.push(`it no longer receives ${removed.join(', ')}`);
	}
	return out;
}

// describeDestination says where a channel sends, without its secret.
export function describeDestination(c: Channel): string {
	if (c.kind === 'matrix' && c.matrix) return `${c.matrix.room_id} on ${c.matrix.homeserver}`;
	return c.webhook_id ? `Webhook ${c.webhook_id}` : 'No webhook yet';
}

// describeSecret says where the secret comes from, or why the channel can't send.
export function describeSecret(c: Channel): { text: string; problem: boolean } {
	if (c.secret_problem) return { text: c.secret_problem, problem: true };
	if (c.secret_source === 'environment') return { text: `From ${c.secret_variable}`, problem: false };
	const by = c.secret_updated_by ? ` by ${c.secret_updated_by}` : '';
	return { text: `Stored, changed ${formatDateTime(c.secret_updated_at)}${by}`, problem: false };
}

// canReplaceSecret says whether the secret can be replaced here: not while it comes from the environment, and not
// without a master key.
export function canReplaceSecret(c: Channel, canStore: boolean): boolean {
	return canStore && c.secret_source !== 'environment';
}

// eventsSummary names a channel's events, shortened: "login, logout and 3 more".
export function eventsSummary(events: string[], max = 3): string {
	if (events.length === 0) return 'No events';
	if (events.length <= max) return events.join(', ');
	return `${events.slice(0, max).join(', ')} and ${events.length - max} more`;
}

export type EventGroup = { group: string; events: NotificationEvent[] };

// groupEvents keeps the server's order, grouped.
export function groupEvents(events: NotificationEvent[]): EventGroup[] {
	const out: EventGroup[] = [];
	for (const e of events) {
		const last = out.at(-1);
		if (last && last.group === e.group) last.events.push(e);
		else out.push({ group: e.group, events: [e] });
	}
	return out;
}

// toInput is the body that saves a channel as it is, with some fields changed: enabling or disabling from the menu
// sends the whole channel, as the API wants.
export function toInput(c: Channel, changes: Partial<ChannelInput> = {}): ChannelInput {
	const base: ChannelInput = {
		kind: c.kind,
		name: c.name,
		env_name: c.env_name ?? '',
		enabled: c.enabled,
		events: [...c.events]
	};
	if (c.kind === 'matrix' && c.matrix) base.matrix = { ...c.matrix };
	return { ...base, ...changes };
}
