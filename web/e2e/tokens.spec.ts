// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Personal API tokens, against the seeded server: making one from the account page and using it as a script would,
// what the form offers, revoking it, the admin tab, and a code asked for with two-factor login on. Each test makes the
// users and roles it needs and deletes them; a token goes with its user.
//
// No test here sends a wrong password, a wrong code or a wrong token secret. Each counts against the per-address login
// limit, which every test in the suite shares (they all come from 127.0.0.1), so a few here would lock later specs out
// of logging in. The Go tests cover those refusals. A revoked token is sent: it has the right secret, so it is refused
// without counting.
import type { APIRequestContext, Browser, Page } from '@playwright/test';
import { apiWrite, expect, logIn, openAs, test, type State, type User } from './fixtures.js';

async function adminPage(browser: Browser, state: State): Promise<Page> {
	const context = await browser.newContext({ baseURL: state.seeded.url });
	const page = await context.newPage();
	await page.goto('/login');
	await logIn(page, state.seeded.fixture.admin);
	await expect(page).not.toHaveURL(/\/login/);
	return page;
}

async function idOf(page: Page, what: 'users' | 'roles', name: string): Promise<number> {
	const res = await page.request.get(`/api/v1/${what}`);
	expect(res.ok()).toBe(true);
	const body = (await res.json()) as Record<string, { id: number; username?: string; name?: string }[]>;
	const found = body[what].find((x) => (x.username ?? x.name) === name);
	if (!found) throw new Error(`no ${what} ${name}`);
	return found.id;
}

// withUser makes a role with the given grants and a user holding it, runs fn, and deletes both.
async function withUser(
	admin: Page,
	name: string,
	grants: { permission: string; scope: string; id?: number }[],
	fn: (user: User) => Promise<void>
) {
	await apiWrite(admin, 'POST', '/api/v1/roles', { name: `e2e-${name}`, description: '', grants });
	const roleID = await idOf(admin, 'roles', `e2e-${name}`);
	const user: User = { username: name, password: `${name}-password-1234`, about: '' };
	await apiWrite(admin, 'POST', '/api/v1/users', { username: user.username, password: user.password, role_ids: [roleID] });
	try {
		await fn(user);
	} finally {
		await apiWrite(admin, 'DELETE', `/api/v1/users/${await idOf(admin, 'users', name)}`);
		await apiWrite(admin, 'DELETE', `/api/v1/roles/${roleID}`);
	}
}

// bearer calls the API as a script would: the token in a header, no cookies, no CSRF token.
function bearer(request: APIRequestContext, token: string) {
	const headers = { Authorization: `Bearer ${token}` };
	return {
		get: (path: string) => request.get(path, { headers }),
		post: (path: string, data?: unknown) => request.post(path, { headers, data })
	};
}

async function openNewToken(page: Page) {
	await page.getByRole('button', { name: 'New token' }).click();
	const dialog = page.getByRole('dialog');
	await expect(dialog.getByRole('heading', { name: 'New API token' })).toBeVisible();
	return dialog;
}

// makeToken fills the form, which must be open, and returns the token the dialog shows once.
async function makeToken(page: Page, user: User, name: string, tick: [string, string][], code?: string): Promise<string> {
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Name').fill(name);
	await dialog.getByLabel('30 days').check();
	for (const [permission, scope] of tick) {
		await dialog.getByRole('group', { name: permission }).getByRole('checkbox', { name: scope }).click();
	}
	await dialog.getByLabel('Your password').fill(user.password);
	if (code !== undefined) await dialog.getByLabel('Code from your app, or a recovery code').fill(code);
	await dialog.getByRole('button', { name: 'Make token' }).click();
	await expect(dialog.getByRole('heading', { name: 'Your new token' })).toBeVisible();
	const token = (await dialog.getByLabel('Token').textContent())?.trim() ?? '';
	expect(token).toMatch(/^prt_[a-z2-7]{16}_[a-z2-7]{52}$/);
	await expect(dialog.locator('pre')).toContainText(`curl -H 'Authorization: Bearer ${token}'`);
	await dialog.getByRole('button', { name: 'Done' }).click();
	await expect(dialog).toBeHidden();
	return token;
}

test('making a token from the account page, using it, and revoking it', async ({ page, browser, state, request }) => {
	const admin = await adminPage(browser, state);
	const inst = state.seeded.fixture.instances[0];
	await withUser(
		admin,
		'tobias',
		[
			{ permission: 'tokens.use', scope: 'all' },
			{ permission: 'domains.view', scope: 'instance', id: inst.id },
			{ permission: 'blocking.toggle', scope: 'instance', id: inst.id }
		],
		async (tobias) => {
			await openAs(page, tobias, '/');
			await page.getByRole('button', { name: 'Account: tobias' }).click();
			await page.getByRole('menuitem', { name: 'API tokens' }).click();
			await expect(page).toHaveURL('/account/tokens');
			await expect(page).toHaveTitle('API tokens · pihole-rbac');
			await expect(page.getByText("You don't have any API tokens.")).toBeVisible();

			// The form offers only what tobias holds, where he holds it: no "All instances", and no other permissions.
			const dialog = await openNewToken(page);
			await expect(dialog.getByRole('group', { name: 'domains.view' }).getByRole('checkbox')).toHaveCount(1);
			await expect(dialog.getByRole('group', { name: 'domains.edit' })).toHaveCount(0);
			await expect(dialog.getByRole('group', { name: 'users.manage' })).toHaveCount(0);
			// Nothing ticked and no password: it says what's missing rather than sending.
			await dialog.getByRole('button', { name: 'Make token' }).click();
			await expect(dialog.getByText('Give the token a name')).toBeVisible();
			await expect(dialog.getByText('Tick at least one permission.')).toBeVisible();
			await expect(dialog.getByText('Enter your password.')).toBeVisible();
			await dialog.getByLabel('Name').fill('half filled');
			await dialog.getByRole('button', { name: 'Cancel' }).click();

			// Opened again, the form starts empty.
			await openNewToken(page);
			await expect(dialog.getByLabel('Name')).toHaveValue('');
			const token = await makeToken(page, tobias, 'home assistant', [['domains.view', inst.name]]);
			const listed = page.getByRole('list', { name: 'API tokens' }).getByRole('listitem').first();
			await expect(listed).toContainText('home assistant');
			await expect(listed).toContainText('Active');
			await expect(listed).toContainText(`domains.view: ${inst.name}`);
			await expect(listed).toContainText('never used');

			// As a script: the grant it was given works, one it wasn't doesn't, nor does anything about accounts.
			const api = bearer(request, token);
			expect((await api.get(`/api/v1/targets/i-${inst.id}/domains`)).status()).toBe(200);
			expect((await api.get(`/api/v1/targets/i-${inst.id}/blocking`)).status()).toBe(200); // any permission on it
			const put = await request.put(`/api/v1/targets/i-${inst.id}/blocking`, {
				headers: { Authorization: `Bearer ${token}` },
				data: { enabled: true }
			});
			expect(put.status()).toBe(403);
			const logout = await api.post('/api/v1/auth/logout');
			expect(logout.status()).toBe(403);
			expect((await logout.json()).error.code).toBe('token_not_allowed');

			await page.reload();
			await expect(listed).toContainText('last used');

			// Revoking asks first, then the token stops at once.
			await listed.getByRole('button', { name: 'Revoke token home assistant' }).click();
			const confirm = page.getByRole('alertdialog');
			await expect(confirm).toContainText('Revoke the token "home assistant"?');
			await confirm.getByRole('button', { name: 'Revoke' }).click();
			await expect(page.getByText('Token "home assistant" revoked.')).toBeVisible();
			await expect(listed).toContainText('Revoked by you');
			await expect(listed.getByRole('button', { name: /Revoke/ })).toHaveCount(0);
			const after = await api.get(`/api/v1/targets/i-${inst.id}/domains`);
			expect(after.status()).toBe(401);
			expect((await after.json()).error.code).toBe('invalid_token');
		}
	);
	await admin.context().close();
});

test('without tokens.use there is no menu item and no New token, and an admin sees and revokes tokens', async ({
	page,
	browser,
	state,
	request
}) => {
	const admin = await adminPage(browser, state);
	const inst = state.seeded.fixture.instances[0];

	// one_instance holds no tokens.use: no menu item, and the page only lists.
	await openAs(page, state.seeded.fixture.one_instance, '/');
	await page.getByRole('button', { name: `Account: ${state.seeded.fixture.one_instance.username}` }).click();
	await expect(page.getByRole('menuitem', { name: 'Two-factor login' })).toBeVisible();
	await expect(page.getByRole('menuitem', { name: 'API tokens' })).toHaveCount(0);
	await page.keyboard.press('Escape');
	await page.goto('/account/tokens');
	await expect(page.getByText("You can't make new tokens: that needs the tokens.use permission.")).toBeVisible();
	await expect(page.getByRole('button', { name: 'New token' })).toHaveCount(0);
	await page.context().clearCookies();

	await withUser(
		admin,
		'ursula',
		[
			{ permission: 'tokens.use', scope: 'all' },
			{ permission: 'domains.view', scope: 'all' }
		],
		async (ursula) => {
			await openAs(page, ursula, '/account/tokens');
			await openNewToken(page);
			// Held at scope all, so "All instances" is offered.
			const token = await makeToken(page, ursula, 'cron', [['domains.view', 'All instances']]);
			expect((await bearer(request, token).get(`/api/v1/targets/i-${inst.id}/domains`)).status()).toBe(200);

			await admin.goto('/admin/sessions');
			await admin.getByRole('tab', { name: /API tokens/ }).click();
			const row = admin.getByRole('listitem').filter({ hasText: 'ursula · cron' });
			await expect(row).toContainText('domains.view: all instances');
			await expect(row.getByText('Active', { exact: true })).toBeVisible();
			// Where Revoke sits in its row, which a note under the token mustn't change.
			const revokeAt = async () => {
				const [r, b] = await Promise.all([row.boundingBox(), row.getByRole('button', { name: /^Revoke/ }).boundingBox()]);
				return { right: Math.round(r!.x + r!.width - b!.x), top: Math.round(b!.y - r!.y) };
			};
			const activeAt = await revokeAt();

			// Without tokens.use the token is refused but not revoked, and the list says so; given back, it is active.
			const roleID = await idOf(admin, 'roles', 'e2e-ursula');
			const setGrants = (grants: { permission: string; scope: string }[]) =>
				apiWrite(admin, 'PUT', `/api/v1/roles/${roleID}/grants`, { grants });
			await setGrants([{ permission: 'domains.view', scope: 'all' }]);
			expect((await bearer(request, token).get(`/api/v1/targets/i-${inst.id}/domains`)).status()).toBe(403);
			await admin.reload();
			await admin.getByRole('tab', { name: /API tokens/ }).click();
			await expect(row.getByText('Refused', { exact: true })).toBeVisible();
			await expect(row).toContainText("Refused: ursula's roles no longer allow using API tokens.");
			expect(await revokeAt()).toEqual(activeAt);
			await setGrants([
				{ permission: 'tokens.use', scope: 'all' },
				{ permission: 'domains.view', scope: 'all' }
			]);
			await admin.reload();
			await admin.getByRole('tab', { name: /API tokens/ }).click();
			await expect(row.getByText('Active', { exact: true })).toBeVisible();
			await expect(row).not.toContainText('Refused');

			await row.getByRole('button', { name: "Revoke ursula's token cron" }).click();
			const confirm = admin.getByRole('alertdialog');
			await expect(confirm).toContainText(`Revoke ursula's token "cron"?`);
			await confirm.getByRole('button', { name: 'Revoke' }).click();
			await expect(admin.getByText(`ursula's token "cron" revoked.`)).toBeVisible();
			await expect(row).toContainText('Revoked by an admin');
			// And ursula sees who did it.
			await page.reload();
			await expect(page.getByRole('list', { name: 'API tokens' })).toContainText('Revoked by an admin');
		}
	);
	await admin.context().close();
});

// totp is the six-digit code for the 30-second step that `at` falls in (RFC 6238), as in totp.spec.ts.
async function totp(secret: string, at: number): Promise<string> {
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const bytes: number[] = [];
	let bits = 0;
	let value = 0;
	for (const c of secret.replace(/\s/g, '').toUpperCase()) {
		value = (value << 5) | alphabet.indexOf(c);
		bits += 5;
		if (bits >= 8) {
			bytes.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	const key = await crypto.subtle.importKey('raw', new Uint8Array(bytes), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const counter = new DataView(new ArrayBuffer(8));
	counter.setBigUint64(0, BigInt(Math.floor(at / 30_000)));
	const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
	const offset = mac[mac.length - 1] & 0x0f;
	const n = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
	return String(n % 1_000_000).padStart(6, '0');
}

test('with two-factor login on, making a token asks for a code', async ({ page, browser, state }) => {
	const admin = await adminPage(browser, state);
	await withUser(
		admin,
		'vera',
		[
			{ permission: 'tokens.use', scope: 'all' },
			{ permission: 'domains.view', scope: 'all' }
		],
		async (vera) => {
			await openAs(page, vera, '/account/tokens');
			// Two-factor login turned on through the API, as the two-factor page would.
			const setup = await apiWrite(page, 'POST', '/api/v1/auth/totp/setup');
			const { secret } = (await setup.json()) as { secret: string };
			await apiWrite(page, 'POST', '/api/v1/auth/totp/confirm', { code: await totp(secret, Date.now()) });
			await page.reload();

			const dialog = await openNewToken(page);
			await dialog.getByLabel('Name').fill('needs a code');
			await dialog.getByRole('group', { name: 'domains.view' }).getByRole('checkbox', { name: 'All instances' }).click();
			await dialog.getByLabel('Your password').fill(vera.password);
			await dialog.getByRole('button', { name: 'Make token' }).click();
			await expect(dialog.getByText('Enter the six-digit code from your app, or a recovery code.')).toBeVisible();
			await dialog.getByRole('button', { name: 'Cancel' }).click();

			// The confirm spent this step's code; the server accepts the next step's.
			await openNewToken(page);
			await makeToken(page, vera, 'with a code', [['domains.view', 'All instances']], await totp(secret, Date.now() + 30_000));
			await expect(page.getByRole('list', { name: 'API tokens' })).toContainText('with a code');
		}
	);
	await admin.context().close();
});

test('an LDAP user makes and uses a token, and an admin sees and revokes it', async ({ page, browser, state, request }) => {
	const admin = await adminPage(browser, state);
	const d = state.seeded.fixture.ldap;
	const inst = state.seeded.fixture.instances[0];
	// LDAP login on, and the staff group (mark is in it) mapped to a role with tokens.use. Put back afterwards.
	await apiWrite(admin, 'PUT', '/api/v1/settings/ldap', {
		url: d.url, bind_dn: d.bind_dn, base_dn: d.base_dn, user_filter: d.user_filter, bind_password: d.bind_password
	});
	await apiWrite(admin, 'PUT', '/api/v1/settings/auth', { methods: ['local', 'ldap'] });
	await apiWrite(admin, 'POST', '/api/v1/roles', {
		name: 'e2e-ldap-tokens', description: '', grants: [{ permission: 'tokens.use', scope: 'all' }, { permission: 'domains.view', scope: 'all' }]
	});
	const roleID = await idOf(admin, 'roles', 'e2e-ldap-tokens');
	const mapped = await apiWrite(admin, 'POST', `/api/v1/roles/${roleID}/ldap-groups`, { group_dn: d.staff_group });
	const mappingID = ((await mapped.json()) as { mapping: { id: number } }).mapping.id;
	const mark: User = { username: 'mark', password: 'mark-ldap-password', about: '' };
	try {
		await openAs(page, mark, '/');
		await page.getByRole('button', { name: 'Account: mark' }).click();
		await page.getByRole('menuitem', { name: 'API tokens' }).click();
		await expect(page).toHaveURL('/account/tokens');
		await openNewToken(page);
		// His directory password, checked with a bind.
		const token = await makeToken(page, mark, 'directory cron', [['domains.view', 'All instances']]);
		const listed = page.getByRole('list', { name: 'API tokens' }).getByRole('listitem').first();
		await expect(listed).toContainText('Active');
		expect((await bearer(request, token).get(`/api/v1/targets/i-${inst.id}/domains`)).status()).toBe(200);

		await admin.goto('/admin/sessions');
		await admin.getByRole('tab', { name: /API tokens/ }).click();
		const row = admin.getByRole('listitem').filter({ hasText: 'mark · directory cron' });
		await expect(row).toContainText('Active');
		await row.getByRole('button', { name: "Revoke mark's token directory cron" }).click();
		await admin.getByRole('alertdialog').getByRole('button', { name: 'Revoke' }).click();
		await expect(row).toContainText('Revoked');
	} finally {
		await apiWrite(admin, 'DELETE', `/api/v1/roles/${roleID}/ldap-groups/${mappingID}`);
		await apiWrite(admin, 'PUT', '/api/v1/settings/auth', { methods: ['local'] });
		await apiWrite(admin, 'DELETE', `/api/v1/roles/${roleID}`);
		await admin.context().close();
	}
});
