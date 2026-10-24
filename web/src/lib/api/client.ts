// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The typed API client. `paths` and `components` are generated from api/openapi.yaml into schema.d.ts by
// openapi-typescript (make generate / .\build.ps1 generate), so a call like api.GET('/api/v1/about') is checked
// against the spec: the path, its parameters, the request body and the response type.
import createClient, { type Middleware } from 'openapi-fetch';
import type { components, paths } from './schema.js';

// Shorthand for the spec's schemas: Schemas['About'], Schemas['Session'], ...
export type Schemas = components['schemas'];
export type ErrorBody = Schemas['ErrorBody'];

// The CSRF token for the current visitor: the anonymous one from GET /auth/csrf before login, the session's after.
// Kept here rather than in a Svelte store because only this module needs to read it; the session store sets it.
let csrfToken: string | null = null;

export function setCSRFToken(token: string | null): void {
	csrfToken = token;
}

const stateChanging = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// openapi-fetch middleware: runs before every request sent through `api`.
const sendCSRFToken: Middleware = {
	onRequest({ request }) {
		if (csrfToken !== null && stateChanging.has(request.method)) {
			request.headers.set('X-CSRF-Token', csrfToken);
		}
		return request;
	}
};

// Paths in the spec already start with /api/v1, and the SPA is served from the same origin as the API, so the base
// URL is empty. In development Vite's dev server proxies /api to the Go server, which keeps it one origin there too.
export const api = createClient<paths>({ baseUrl: '', credentials: 'same-origin' });
api.use(sendCSRFToken);

// A failed API call. `code` is the server's error code (see ErrorBody in the spec), or one of two codes made up
// here: network_error when no answer arrived, and unexpected_response when the answer wasn't the error envelope.
export class ApiError extends Error {
	readonly status: number;
	readonly code: string;
	readonly details: Record<string, unknown>;

	constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
		this.code = code;
		this.details = details;
	}
}

function isErrorEnvelope(body: unknown): body is { error: ErrorBody } {
	if (typeof body !== 'object' || body === null || !('error' in body)) return false;
	const e = (body as { error: unknown }).error;
	return (
		typeof e === 'object' &&
		e !== null &&
		typeof (e as ErrorBody).code === 'string' &&
		typeof (e as ErrorBody).message === 'string'
	);
}

function toApiError(response: Response, body: unknown): ApiError {
	if (isErrorEnvelope(body)) {
		const { code, message, details } = body.error;
		return new ApiError(response.status, code, message, details ?? {});
	}
	return new ApiError(
		response.status,
		'unexpected_response',
		`The server answered with an unexpected response (HTTP ${response.status}).`
	);
}

// What every openapi-fetch call resolves to: either data or error is set, never both.
type FetchResult<T> = { data?: T; error?: unknown; response: Response };

// unwrap turns an openapi-fetch call into its data, or throws an ApiError, so callers can use try/catch instead of
// checking `error` after every call:
//
//	const about = await unwrap(api.GET('/api/v1/about'));
export async function unwrap<T>(call: Promise<FetchResult<T>>): Promise<T> {
	let result: FetchResult<T>;
	try {
		result = await call;
	} catch {
		// fetch only rejects when no response arrived: the server is down, or the network failed.
		throw new ApiError(0, 'network_error', "The server couldn't be reached. Check your connection and try again.");
	}
	const { data, error, response } = result;
	if (error !== undefined || !response.ok) throw toApiError(response, error);
	return data as T;
}
