// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError, unwrap } from './client.js';

// What openapi-fetch resolves to: data on a 2xx, error (the parsed body) otherwise.
function result<T>(status: number, body: { data?: T; error?: unknown }) {
	return Promise.resolve({ ...body, response: new Response(null, { status }) });
}

async function failure(call: ReturnType<typeof result>): Promise<ApiError> {
	try {
		await unwrap(call);
	} catch (e) {
		expect(e).toBeInstanceOf(ApiError);
		return e as ApiError;
	}
	throw new Error('unwrap did not throw');
}

describe('unwrap', () => {
	it('returns the data of a successful call, including a 207', async () => {
		await expect(unwrap(result(200, { data: { ok: true } }))).resolves.toEqual({ ok: true });
		await expect(unwrap(result(207, { data: { results: [] } }))).resolves.toEqual({ results: [] });
	});

	it("turns the server's error envelope into an ApiError with its code and details", async () => {
		const e = await failure(
			result(403, {
				error: {
					error: { code: 'forbidden', message: 'Not allowed.', details: { permission: 'users.manage' } }
				}
			})
		);
		expect(e.status).toBe(403);
		expect(e.code).toBe('forbidden');
		expect(e.message).toBe('Not allowed.');
		expect(e.details).toEqual({ permission: 'users.manage' });
	});

	it('gives details as an empty object when the envelope has none', async () => {
		const e = await failure(result(401, { error: { error: { code: 'unauthenticated', message: 'Log in.' } } }));
		expect(e.details).toEqual({});
	});

	it('calls a body that isn\'t the envelope an unexpected response', async () => {
		const e = await failure(result(502, { error: 'Bad Gateway' }));
		expect(e.code).toBe('unexpected_response');
		expect(e.status).toBe(502);
		expect(e.message).toMatch(/502/);
	});

	it('calls a failed fetch a network error', async () => {
		const e = await failure(Promise.reject(new TypeError('Failed to fetch')));
		expect(e.code).toBe('network_error');
		expect(e.status).toBe(0);
	});
});
