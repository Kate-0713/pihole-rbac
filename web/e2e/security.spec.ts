// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// What the browser receives: the security headers on the page and the API, and the CSRF and Origin checks on a
// write, as the real binary sends and enforces them.
import { expect, test } from './fixtures.js';

test('the page is served with the strict CSP, its script hash, and the other security headers', async ({ page }) => {
	const res = await page.goto('/login');
	const headers = res!.headers();
	const csp = headers['content-security-policy'];
	expect(csp).toContain("default-src 'self'");
	expect(csp).toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/);
	expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
	expect(csp).toContain("frame-ancestors 'none'");
	expect(headers['x-content-type-options']).toBe('nosniff');
	expect(headers['referrer-policy']).toBe('same-origin');
	// The app booted under that policy: the form is there, and the fixture saw no CSP violation.
	await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible();
});

test('API answers are never cached', async ({ request }) => {
	const res = await request.get('/api/v1/about');
	expect(res.headers()['cache-control']).toBe('no-store');
});

test('a write without the CSRF token, or from another origin, is refused', async ({ request, state }) => {
	const { admin } = state.seeded.fixture;
	const origin = state.seeded.url;
	const { csrf_token: anon } = await (await request.get('/api/v1/auth/csrf')).json();
	const login = await request.post('/api/v1/auth/login', {
		data: { username: admin.username, password: admin.password },
		headers: { 'X-CSRF-Token': anon, Origin: origin }
	});
	expect(login.status()).toBe(200);
	const { csrf_token } = await login.json();
	const put = (headers: Record<string, string>) =>
		request.put('/api/v1/targets/i-1/blocking', { data: { enabled: true }, headers });

	let res = await put({ Origin: origin });
	expect(res.status()).toBe(403);
	expect((await res.json()).error.code).toBe('csrf_failed');

	res = await put({ Origin: 'https://evil.example', 'X-CSRF-Token': csrf_token });
	expect(res.status()).toBe(403);

	// With both, the write goes through and answers with a result per instance.
	res = await put({ Origin: origin, 'X-CSRF-Token': csrf_token });
	expect(res.status()).toBe(200);
	expect((await res.json()).results).toEqual([
		expect.objectContaining({ instance: 'pihole1', status: 'ok', blocking: expect.objectContaining({ blocking: 'enabled' }) })
	]);
});
