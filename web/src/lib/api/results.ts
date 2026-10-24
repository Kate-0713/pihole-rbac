// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Every Pi-hole write (blocking, DNS restart, domain and client changes) answers with one result per instance it
// acted on: one for an instance target, one per member for a mirrored group. See WriteResults in api/openapi.yaml.
//
//   200  every result is ok: unwrap() returns { results }
//   207  some ok, some not: unwrap() also returns { results } (it's a 2xx), so check summarise(results).allOk
//   4xx/5xx  none ok: unwrap() throws an ApiError for the first failure, and failedResults(err) has every result
//
// So a page calls the write, then hands either the returned results or failedResults(err) to the same component.
import { ApiError, type Schemas } from './client.js';

export type WriteStatus = Schemas['WriteStatus'];
export type WriteError = Schemas['WriteError'];

// The fields every operation's result has. Each operation adds its own (entry, blocking, confirmed), present when
// the status is ok; the generated types (Schemas['DomainWriteResult'] and so on) have them.
export type InstanceResult = {
	instance: string;
	instance_id: number;
	status: WriteStatus;
	error?: WriteError;
};

function isInstanceResult(x: unknown): x is InstanceResult {
	if (typeof x !== 'object' || x === null) return false;
	const r = x as Record<string, unknown>;
	return (
		typeof r.instance === 'string' &&
		typeof r.instance_id === 'number' &&
		(r.status === 'ok' || r.status === 'failed' || r.status === 'skipped')
	);
}

// The per-instance results carried by a failed write's error (details.results), or null when the error isn't one.
// The details are untyped in the spec, so each entry is checked rather than trusted.
export function failedResults(err: unknown): InstanceResult[] | null {
	if (!(err instanceof ApiError)) return null;
	const results = err.details['results'];
	if (!Array.isArray(results)) return null;
	return results.filter(isInstanceResult);
}

export type ResultSummary<T extends InstanceResult> = {
	ok: T[];
	failed: T[]; // asked, and the change failed
	skipped: T[]; // not asked: found down moments ago, or can't be used
	allOk: boolean;
};

export function summarise<T extends InstanceResult>(results: readonly T[]): ResultSummary<T> {
	const ok = results.filter((r) => r.status === 'ok');
	const failed = results.filter((r) => r.status === 'failed');
	const skipped = results.filter((r) => r.status === 'skipped');
	return { ok, failed, skipped, allOk: results.length > 0 && ok.length === results.length };
}
