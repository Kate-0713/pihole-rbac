// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
	canReplaceSecret,
	describeDestination,
	describeSecret,
	envNameProblem,
	eventsSummary,
	groupEvents,
	guardWarnings,
	homeserverProblem,
	nameProblem,
	needsSecret,
	normalizeHomeserver,
	roomProblem,
	secretVariable,
	toInput,
	tokenProblem,
	webhookProblem,
	type Channel,
	type ChannelForm
} from './notifications.js';

const discord: Channel = {
	id: 1,
	kind: 'discord',
	name: 'Ops',
	enabled: true,
	events: ['login', 'logout'],
	webhook_id: '123',
	secret_source: 'stored',
	secret_updated_at: '2026-10-25T12:00:00Z',
	secret_updated_by: 'admin',
	created_at: '2026-10-25T12:00:00Z'
};

const matrix: Channel = {
	...discord,
	id: 2,
	kind: 'matrix',
	name: 'Room',
	webhook_id: undefined,
	matrix: { homeserver: 'https://matrix.example.org', room_id: '!r:example.org', allow_http: false }
};

const form = (c: Channel, changes: Partial<ChannelForm> = {}): ChannelForm => ({
	homeserver: c.matrix?.homeserver ?? '',
	allowHTTP: c.matrix?.allow_http ?? false,
	enabled: c.enabled,
	events: [...c.events],
	secret: '',
	...changes
});

describe('rules', () => {
	it('names and env names', () => {
		expect(nameProblem('Ops')).toBeNull();
		expect(nameProblem('  ')).not.toBeNull();
		expect(nameProblem('x'.repeat(65))).not.toBeNull();
		expect(envNameProblem('')).toBeNull();
		expect(envNameProblem('OPS_1')).toBeNull();
		expect(envNameProblem('ops')).not.toBeNull();
		expect(secretVariable('OPS')).toBe('PIHOLE_RBAC_NOTIFY_OPS_SECRET');
	});

	it.each([
		['https://discord.com/api/webhooks/123/abc-DEF_1', true],
		['https://DISCORDAPP.com/api/webhooks/1/x', true],
		['https://discord.com:443/api/webhooks/1/x', true],
		['', false],
		['http://discord.com/api/webhooks/1/x', false],
		['https://discord.com.evil.example/api/webhooks/1/x', false],
		['https://192.168.1.10/api/webhooks/1/x', false],
		['https://discord.com/api/webhooks/1/x?wait=true', false],
		['https://discord.com/api/webhooks/abc/x', false]
	])('webhook %s', (url, ok) => {
		expect(webhookProblem(url) === null).toBe(ok);
	});

	it.each([
		['https://matrix.example.org', false, true],
		['https://10.0.0.5:8448/base', false, true],
		['http://synapse.lan:8008', false, false],
		['http://synapse.lan:8008', true, true],
		['ftp://example.org', true, false],
		['https://u:p@example.org', false, false],
		['https://example.org?x=1', false, false],
		['not a url', false, false]
	])('homeserver %s (allow http %s)', (h, allow, ok) => {
		expect(homeserverProblem(h, allow) === null).toBe(ok);
	});

	it('rooms and tokens', () => {
		expect(roomProblem('!abc:example.org')).toBeNull();
		expect(roomProblem('!abc:example.org:8448')).toBeNull();
		expect(roomProblem('#alias:example.org')).not.toBeNull();
		expect(tokenProblem('syt_abc_123')).toBeNull();
		expect(tokenProblem('has space')).not.toBeNull();
		expect(tokenProblem('')).not.toBeNull();
	});

	it('normalizes a homeserver as the server does', () => {
		expect(normalizeHomeserver('HTTPS://Matrix.Example.org/')).toBe('https://matrix.example.org');
		expect(normalizeHomeserver('https://m.lan:8448/base/')).toBe('https://m.lan:8448/base');
	});
});

describe('needsSecret', () => {
	it('asks for the token when a Matrix homeserver or plain HTTP changes', () => {
		expect(needsSecret(matrix, form(matrix))).toBe(false);
		expect(needsSecret(matrix, form(matrix, { homeserver: 'https://MATRIX.example.org/' }))).toBe(false);
		expect(needsSecret(matrix, form(matrix, { homeserver: 'https://other.example' }))).toBe(true);
		expect(needsSecret(matrix, form(matrix, { allowHTTP: true }))).toBe(true);
	});

	it("doesn't for Discord, a new channel, or one without a token", () => {
		expect(needsSecret(discord, form(discord))).toBe(false);
		expect(needsSecret(null, form(matrix, { homeserver: 'https://x' }))).toBe(false);
		expect(needsSecret({ ...matrix, secret_source: 'none' }, form(matrix, { homeserver: 'https://x' }))).toBe(false);
	});
});

describe('guardWarnings', () => {
	it('says what the old destination will be told', () => {
		expect(guardWarnings(discord, form(discord))).toEqual([]);
		expect(guardWarnings(discord, form(discord, { events: ['login', 'logout', 'domain_add'] }))).toEqual([]);
		expect(guardWarnings(discord, form(discord, { events: ['login'] }))).toEqual(['it no longer receives logout']);
		expect(guardWarnings(discord, form(discord, { enabled: false, events: [] }))).toEqual(['it was disabled']);
		expect(guardWarnings(discord, form(discord, { secret: 'https://discord.com/api/webhooks/9/x' }))).toEqual([
			'it now sends somewhere else'
		]);
		expect(guardWarnings(matrix, form(matrix, { homeserver: 'https://other.example' }))).toEqual(['it now sends somewhere else']);
	});

	it('warns nobody where there is nothing to send with', () => {
		expect(guardWarnings(null, form(discord, { enabled: false }))).toEqual([]);
		expect(guardWarnings({ ...discord, secret_source: 'none' }, form(discord, { enabled: false }))).toEqual([]);
		expect(guardWarnings({ ...discord, secret_problem: 'unreadable' }, form(discord, { enabled: false }))).toEqual([]);
		// A disabled channel losing events isn't told: it isn't receiving them.
		expect(guardWarnings({ ...discord, enabled: false }, form({ ...discord, enabled: false }, { events: [] }))).toEqual([]);
	});
});

describe('summaries', () => {
	it('destinations and secrets', () => {
		expect(describeDestination(discord)).toBe('Webhook 123');
		expect(describeDestination({ ...discord, webhook_id: undefined })).toBe('No webhook yet');
		expect(describeDestination(matrix)).toBe('!r:example.org on https://matrix.example.org');
		expect(describeSecret({ ...discord, secret_problem: 'No webhook URL is set.' })).toEqual({ text: 'No webhook URL is set.', problem: true });
		expect(describeSecret({ ...discord, secret_source: 'environment', secret_variable: 'PIHOLE_RBAC_NOTIFY_OPS_SECRET' }).text).toBe(
			'From PIHOLE_RBAC_NOTIFY_OPS_SECRET'
		);
		expect(describeSecret(discord).text).toMatch(/^Stored, changed .* by admin$/);
	});

	it('when a secret can be replaced', () => {
		expect(canReplaceSecret(discord, true)).toBe(true);
		expect(canReplaceSecret(discord, false)).toBe(false);
		expect(canReplaceSecret({ ...discord, secret_source: 'environment' }, true)).toBe(false);
	});

	it('events', () => {
		expect(eventsSummary([])).toBe('No events');
		expect(eventsSummary(['a', 'b'])).toBe('a, b');
		expect(eventsSummary(['a', 'b', 'c', 'd', 'e'])).toBe('a, b, c and 2 more');
		expect(
			groupEvents([
				{ name: 'login', group: 'Sign-in', description: '' },
				{ name: 'logout', group: 'Sign-in', description: '' },
				{ name: 'domain_add', group: 'Pi-hole', description: '' }
			]).map((g) => [g.group, g.events.length])
		).toEqual([
			['Sign-in', 2],
			['Pi-hole', 1]
		]);
	});

	it('saves a channel as it is, with changes', () => {
		expect(toInput(discord, { enabled: false })).toEqual({
			kind: 'discord',
			name: 'Ops',
			env_name: '',
			enabled: false,
			events: ['login', 'logout']
		});
		expect(toInput(matrix).matrix).toEqual(matrix.matrix);
	});
});
