// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiError } from '#lib/api/client.js';
import { restartsLogin } from './totp.js';

describe('restartsLogin', () => {
	it.each([
		['login_expired', 401],
		['invalid_credentials', 401],
		['no_access', 403]
	])('goes back to the password for %s', (code, status) => {
		expect(restartsLogin(new ApiError(status, code, 'x'))).toBe(true);
	});

	it.each([
		['totp_invalid', 401],
		['rate_limited', 429],
		['validation_failed', 400],
		['network_error', 0],
		['internal', 500]
	])('keeps the code form for %s', (code, status) => {
		expect(restartsLogin(new ApiError(status, code, 'x'))).toBe(false);
	});

	it('keeps the code form for an error that is not from the server', () => {
		expect(restartsLogin(new Error('boom'))).toBe(false);
		expect(restartsLogin(undefined)).toBe(false);
	});
});
