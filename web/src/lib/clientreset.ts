// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The client reset page's helpers: browser-side copies of the server's rules for a rule and the schedule
// (checkInput in internal/clientreset and ResetSchedule.Validate in internal/loginsettings), so a form can say what's
// wrong before it is sent; the conversions between the form's rows and the API's rules; and the words the page uses
// for a run. The server checks everything again.
import type { Schemas } from '#lib/api/client.js';
import { controlChars } from '#lib/pihole.js';

export type Rule = Schemas['ClientResetRule'];
export type Rules = Schemas['ClientResetRules'];
export type RulesInput = Schemas['ClientResetRulesInput'];
export type Match = Schemas['ClientResetMatch'];
export type Scope = Schemas['ClientResetScope'];
export type Run = Schemas['ClientResetRun'];
export type RunList = Schemas['ClientResetRunList'];
export type InstanceResult = Schemas['ClientResetInstanceResult'];
export type Preview = Schemas['ClientResetPreview'];
export type Schedule = Schemas['ClientResetSchedule'];

export const maxRules = 500;
export const maxGroupsPerRule = 50;
export const maxNameChars = 255;

export const matchLabel: Record<Match, string> = { names: 'Exact names', prefixes: 'Name prefixes' };

// A rule as the form edits it: the scope as "instance:1" or "group:2", and the groups as one comma-separated text.
export type RuleRow = { scope: string; prefix: string; match: Match; groups: string };

export const emptyRow = (): RuleRow => ({ scope: '', prefix: '', match: 'names', groups: '' });

export function scopeKey(scope: Scope, id: number): string {
	return `${scope}:${id}`;
}

// parseGroupList reads comma-separated Pi-hole group names or prefixes: trimmed, empty ones and exact repeats
// dropped. Names are matched exactly on the Pi-hole, so case matters and "Kids" and "kids" are both kept.
export function parseGroupList(text: string): string[] {
	const out: string[] = [];
	for (const raw of text.split(',')) {
		const name = raw.trim();
		if (name !== '' && !out.includes(name)) out.push(name);
	}
	return out;
}

export function toRuleRows(rules: Rule[]): RuleRow[] {
	return rules.map((r) => ({
		scope: scopeKey(r.scope, r.id),
		prefix: r.comment_prefix,
		match: r.group_match,
		groups: r.pihole_groups.join(', ')
	}));
}

// nameProblem checks a prefix or group name as the server's checkName does: 1-255 characters, no control characters,
// and not only spaces. A comment prefix isn't trimmed, since it is matched exactly.
function nameProblem(s: string): boolean {
	return [...s].length === 0 || [...s].length > maxNameChars || controlChars.test(s) || s.trim() === '';
}

// rulesProblem checks the rows as the server would, and says what's wrong with the first that breaks a rule.
export function rulesProblem(rows: RuleRow[]): string | null {
	if (rows.length > maxRules) return `At most ${maxRules} rules.`;
	const seen = new Set<string>();
	for (const [i, r] of rows.entries()) {
		const n = `Rule ${i + 1}: `;
		if (r.scope === '') return `${n}choose an instance or mirrored group.`;
		if (nameProblem(r.prefix)) {
			return `${n}the comment prefix is 1-${maxNameChars} characters, with no control characters, and not only spaces.`;
		}
		const key = `${r.scope}|${r.prefix}`;
		if (seen.has(key)) return `${n}"${r.prefix}" is already used on that instance or group.`;
		seen.add(key);
		const groups = parseGroupList(r.groups);
		if (groups.length === 0) return `${n}name at least one Pi-hole group.`;
		if (groups.length > maxGroupsPerRule) return `${n}at most ${maxGroupsPerRule} Pi-hole groups.`;
		if (groups.some(nameProblem)) return `${n}a Pi-hole group is 1-${maxNameChars} characters, with no control characters.`;
	}
	return null;
}

// toRulesInput is the body that saves the rows.
export function toRulesInput(rows: RuleRow[]): RulesInput {
	return {
		rules: rows.map((r) => {
			const [scope, id] = r.scope.split(':');
			return {
				scope: scope as Scope,
				id: Number(id),
				comment_prefix: r.prefix,
				group_match: r.match,
				pihole_groups: parseGroupList(r.groups)
			};
		})
	};
}

// describeRule says what a rule does, in a line: `"TEST-" → AUTOSET-lab, AUTOSET-staff`.
export function describeRule(r: Pick<Rule, 'comment_prefix' | 'group_match' | 'pihole_groups'>): string {
	const groups = r.group_match === 'prefixes' ? r.pihole_groups.map((g) => `${g}…`) : r.pihole_groups;
	return `"${r.comment_prefix}" → ${groups.join(', ')}`;
}

// byScope groups the rules by what they are set on, keeping the server's order (instances first, then by name).
export function byScope(rules: Rule[]): { key: string; scope: Scope; name: string; rules: Rule[] }[] {
	const out: { key: string; scope: Scope; name: string; rules: Rule[] }[] = [];
	for (const r of rules) {
		const key = scopeKey(r.scope, r.id);
		const last = out.at(-1);
		if (last?.key === key) last.rules.push(r);
		else out.push({ key, scope: r.scope, name: r.name, rules: [r] });
	}
	return out;
}

// Runs.

export const runStatusLabel: Record<Run['status'], string> = {
	running: 'Running',
	ok: 'Done',
	partial: 'Partly done',
	failed: 'Failed'
};

export const instanceStatusLabel: Record<InstanceResult['status'], string> = {
	ok: 'Done',
	partial: 'Partly done',
	failed: 'Failed',
	skipped: 'Not reached'
};

const codeWords: Record<string, string> = {
	pihole_group_missing: "the rule's groups aren't all on this Pi-hole",
	no_target_groups: "no group on this Pi-hole matches the rule's prefixes",
	pihole_unreachable: "the Pi-hole didn't respond",
	pihole_auth_rejected: "the Pi-hole refused the app's password",
	pihole_status_error: 'the Pi-hole answered, but not as expected',
	pihole_rejected: 'the Pi-hole refused the change',
	instance_password_missing: "the instance's password isn't set",
	instance_misconfigured: "the instance's settings can't be used",
	not_found: 'the instance is no longer enabled'
};

// describeCode says what an error code from a run means.
export function describeCode(code: string): string {
	return codeWords[code] ?? code;
}

function plural(n: number, word: string): string {
	return `${n} ${word}${n === 1 ? '' : 's'}`;
}

// runCounts adds up a run's (or a preview's) instances.
export function runCounts(instances: InstanceResult[]): {
	reset: number;
	failed: number;
	unchanged: number;
	unread: number;
	broken: number;
} {
	let reset = 0;
	let failed = 0;
	let unchanged = 0;
	let unread = 0;
	const broken = new Set<string>(); // rules that can't run on some instance, by prefix
	for (const i of instances) {
		reset += i.reset.length;
		failed += i.failed.length;
		unchanged += i.unchanged;
		if (i.code) unread++;
		for (const p of i.problems) broken.add(p.prefix);
	}
	return { reset, failed, unchanged, unread, broken: broken.size };
}

// describeRun says in a few words what a run did: "2 clients reset, 1 failed".
export function describeRun(run: Pick<Run, 'status' | 'instances' | 'error'>): string {
	if (run.status === 'running') return 'Running…';
	if (run.error) return run.error;
	const c = runCounts(run.instances);
	const parts: string[] = [];
	if (c.reset > 0) parts.push(`${plural(c.reset, 'client')} reset`);
	if (c.failed > 0) parts.push(`${c.failed} failed`);
	if (c.unread > 0) parts.push(`${plural(c.unread, 'instance')} not reached`);
	if (c.broken > 0) parts.push(`${plural(c.broken, 'rule')} can't run`);
	if (parts.length === 0) return 'Nothing to change';
	return parts.join(', ');
}

// describePreview says what running would do: "Would reset 2 clients on pihole1".
export function describePreview(p: Preview): string {
	const c = runCounts(p.instances);
	if (c.reset === 0) return 'Nothing to reset: every matching client is already in its groups.';
	const where = p.instances.filter((i) => i.reset.length > 0).map((i) => i.instance);
	return `Would reset ${plural(c.reset, 'client')} on ${where.join(', ')}.`;
}

// The schedule.

export const timePattern = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

// isTimeZone says whether the browser knows a time zone name. The server checks it against its own database, which
// is the same IANA one.
export function isTimeZone(zone: string): boolean {
	if (zone === '' || zone === 'Local' || zone.length > 64) return false;
	try {
		new Intl.DateTimeFormat('en', { timeZone: zone });
		return true;
	} catch {
		return false;
	}
}

// scheduleProblem says what's wrong with a schedule, as the server would.
export function scheduleProblem(s: Schedule): string | null {
	if (!timePattern.test(s.time)) return 'The time is HH:MM, from 00:00 to 23:59.';
	if (!isTimeZone(s.time_zone)) return `"${s.time_zone}" isn't a time zone, such as Europe/London or UTC.`;
	return null;
}

// timeZones lists the browser's time zones for the picker, with UTC first.
export function timeZones(): string[] {
	const supported = (Intl as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.('timeZone') ?? [];
	return ['UTC', ...supported.filter((z) => z !== 'UTC')];
}

// browserZone is the browser's own time zone, suggested for a new schedule.
export function browserZone(): string {
	return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
}

// zoneOffset is how far a zone's wall clock is ahead of UTC at an instant, in milliseconds.
function zoneOffset(at: number, zone: string): number {
	const parts = new Intl.DateTimeFormat('en-US', {
		timeZone: zone,
		hourCycle: 'h23',
		year: 'numeric',
		month: '2-digit',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit'
	}).formatToParts(new Date(at));
	const get = (t: string) => Number(parts.find((p) => p.type === t)?.value);
	return Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second')) - Math.floor(at / 1000) * 1000;
}

// zoneDate is the zone's calendar date at an instant.
function zoneDate(at: number, zone: string): { y: number; m: number; d: number } {
	const local = new Date(at + zoneOffset(at, zone));
	return { y: local.getUTCFullYear(), m: local.getUTCMonth(), d: local.getUTCDate() };
}

// nextRun says when an enabled schedule next runs after `now`, or null when it is off or invalid. It follows the
// server's NextRun: a time the clocks skip comes out an hour later.
export function nextRun(s: Schedule, now: Date): Date | null {
	if (!s.enabled || scheduleProblem(s) !== null) return null;
	const [h, min] = s.time.split(':').map(Number);
	const today = zoneDate(now.getTime(), s.time_zone);
	for (let i = 0; i < 3; i++) {
		// The wall-clock time as if it were UTC, then moved back by the zone's offset: once with the offset at that
		// guess, and again in case the offset is different at the result (near a daylight saving change).
		const wall = Date.UTC(today.y, today.m, today.d + i, h, min);
		let at = wall - zoneOffset(wall, s.time_zone);
		at = wall - zoneOffset(at, s.time_zone);
		if (at > now.getTime()) return new Date(at);
	}
	return null;
}
