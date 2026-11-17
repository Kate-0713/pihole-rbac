// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Two-factor login, against the seeded server: setting it up, logging in with a code or a recovery code, turning it
// off, a role that requires it, and an admin's controls. Each test makes users and roles of its own and deletes them,
// so other tests never meet a code prompt. The codes are made here as an authenticator app makes them (RFC 6238).
import type { Browser, Page } from '@playwright/test';
import { apiWrite, expect, logIn, openAs, test, type State, type User } from './fixtures.js';

// base32Decode reads the secret the setup page shows (spaces allowed, no padding).
function base32Decode(s: string): Uint8Array<ArrayBuffer> {
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const clean = s.replace(/\s/g, '').toUpperCase();
	const out: number[] = [];
	let bits = 0;
	let value = 0;
	for (const c of clean) {
		const i = alphabet.indexOf(c);
		if (i < 0) throw new Error(`not base32: ${c}`);
		value = (value << 5) | i;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return new Uint8Array(out);
}

// totp is the six-digit code for the 30-second step that `at` falls in. Web Crypto is built into Node, as in a
// browser, so no package is needed.
async function totp(secret: string, at: number): Promise<string> {
	const key = await crypto.subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const counter = new DataView(new ArrayBuffer(8));
	counter.setBigUint64(0, BigInt(Math.floor(at / 30_000)));
	const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
	const offset = mac[mac.length - 1] & 0x0f;
	const n = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
	return String(n % 1_000_000).padStart(6, '0');
}

// A code can be used once. After one for the current step, the server still accepts the next step's (it allows a
// clock a step ahead), so a test gets two codes without waiting. Later logins use recovery codes.
const nowCode = (secret: string) => totp(secret, Date.now());
const nextCode = (secret: string) => totp(secret, Date.now() + 30_000);

// adminPage logs the admin in, in a context of its own, and leaves it open for the test to use.
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

async function accountMenu(page: Page, username: string) {
	await page.getByRole('button', { name: `Account: ${username}` }).click();
	return page.getByRole('menu');
}

async function logOut(page: Page, username: string) {
	await (await accountMenu(page, username)).getByRole('menuitem', { name: 'Log out' }).click();
	await expect(page).toHaveURL('/login');
}

// setUp goes through the setup on the two-factor page, which must be showing, and returns the secret and the
// recovery codes.
async function setUp(page: Page): Promise<{ secret: string; codes: string[] }> {
	await page.getByRole('button', { name: 'Set up two-factor login' }).click();
	await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible();
	const secret = ((await page.getByLabel('Secret key').textContent()) ?? '').replace(/\s/g, '');
	expect(secret).toMatch(/^[A-Z2-7]{32}$/);

	await page.getByLabel('Enter the 6-digit code the app shows').fill('000000');
	await page.getByRole('button', { name: 'Turn on' }).click();
	// One chance in a million that 000000 is right; the check is that a wrong code is refused and the form stays.
	await expect(page.getByRole('alert').filter({ hasText: "That code isn't right" })).toBeVisible();

	await page.getByLabel('Enter the 6-digit code the app shows').fill(await nowCode(secret));
	await page.getByRole('button', { name: 'Turn on' }).click();
	const list = page.getByRole('region', { name: 'Recovery codes' }).getByRole('listitem');
	await expect(list).toHaveCount(10);
	const codes = await list.allTextContents();
	for (const c of codes) expect(c).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);
	return { secret, codes };
}

// The code step of the login page, after the password.
async function enterCode(page: Page, code: string) {
	await expect(page.getByLabel('Two-factor code')).toBeVisible();
	await page.getByLabel('Two-factor code').fill(code);
	await page.getByRole('button', { name: 'Verify' }).click();
}

test('setting up two-factor login, logging in with a code and a recovery code, and turning it off', async ({
	page,
	state,
	browser
}) => {
	const admin = await adminPage(browser, state);
	const tess: User = { username: 'tess', password: 'tess-password-123', about: '' };
	await apiWrite(admin, 'POST', '/api/v1/users', {
		username: tess.username,
		password: tess.password,
		role_ids: [await idOf(admin, 'roles', 'reader')]
	});

	await openAs(page, tess, '/');
	await (await accountMenu(page, 'tess')).getByRole('menuitem', { name: 'Two-factor login' }).click();
	await expect(page).toHaveURL('/account/two-factor');
	await expect(page).toHaveTitle('Two-factor login · pihole-rbac');
	await expect(page.getByText('Two-factor login is off.', { exact: true })).toBeVisible();

	const { secret, codes } = await setUp(page);
	await page.getByRole('button', { name: "I've saved them" }).click();
	await expect(page.getByText('Two-factor login is on.', { exact: true })).toBeVisible();
	await expect(page.getByText('10 of 10 recovery codes left.')).toBeVisible();

	// The password alone now leads to the code step. A wrong code is refused there and the form stays.
	await logOut(page, 'tess');
	await logIn(page, tess);
	await enterCode(page, '000000');
	await expect(page.getByRole('alert')).toContainText("That code isn't right");
	await expect(page).toHaveURL('/login');
	await enterCode(page, await nextCode(secret));
	await expect(page).toHaveURL('/dashboard?target=i-1');

	// A recovery code, as written down, works once.
	await logOut(page, 'tess');
	await logIn(page, tess);
	await enterCode(page, codes[0]);
	await expect(page).not.toHaveURL(/\/login/);
	await logOut(page, 'tess');
	await logIn(page, tess);
	await enterCode(page, codes[0]);
	await expect(page.getByRole('alert')).toContainText("That code isn't right");
	// Start again goes back to the password.
	await page.getByRole('button', { name: 'Start again' }).click();
	await expect(page.getByLabel('Password')).toBeVisible();
	await logIn(page, tess);
	await enterCode(page, codes[1]);
	await expect(page).not.toHaveURL(/\/login/);

	// Turning it off asks for the password and a code; afterwards the password alone logs in.
	await page.goto('/account/two-factor');
	await expect(page.getByText('8 of 10 recovery codes left.')).toBeVisible();
	await page.getByRole('button', { name: 'Turn off' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Password').fill('not-the-password');
	await dialog.getByLabel('Code from your app, or a recovery code').fill(codes[2]);
	await dialog.getByRole('button', { name: 'Turn off' }).click();
	await expect(dialog.getByRole('alert')).toContainText('Your password is wrong.');
	await dialog.getByLabel('Password').fill(tess.password);
	await dialog.getByLabel('Code from your app, or a recovery code').fill(codes[2]);
	await dialog.getByRole('button', { name: 'Turn off' }).click();
	await expect(page.getByText('Two-factor login is off.', { exact: true })).toBeVisible();

	await logOut(page, 'tess');
	await logIn(page, tess);
	await expect(page).toHaveURL('/dashboard?target=i-1');

	await apiWrite(admin, 'DELETE', `/api/v1/users/${await idOf(admin, 'users', 'tess')}`);
	await admin.context().close();
});

test('a role that requires two-factor login holds its holders to setting it up, and an admin can exempt or reset them', async ({
	page,
	state,
	browser
}) => {
	const admin = await adminPage(browser, state);
	await apiWrite(admin, 'POST', '/api/v1/roles', {
		name: 'e2e-2fa-staff',
		description: 'domains.view everywhere',
		grants: [{ permission: 'domains.view', scope: 'all' }]
	});
	const roleID = await idOf(admin, 'roles', 'e2e-2fa-staff');
	const uma: User = { username: 'uma', password: 'uma-password-1234', about: '' };
	await apiWrite(admin, 'POST', '/api/v1/users', { username: uma.username, password: uma.password, role_ids: [roleID] });

	// uma is working when an admin makes her role require two-factor login, from the role's page.
	await openAs(page, uma, '/');
	await expect(page.getByRole('link', { name: 'Domains' })).toBeVisible();
	await admin.goto(`/admin/roles/${roleID}`);
	await admin.getByRole('checkbox', { name: 'Require two-factor login' }).click();
	await expect(admin.getByText('Holders of e2e-2fa-staff must now use two-factor login.')).toBeVisible();
	await admin.goto('/admin/roles');
	await expect(admin.getByRole('row').filter({ hasText: 'e2e-2fa-staff' })).toContainText('Two-factor required');

	// Her next request is refused, and the app takes her to set it up. Nothing else can be reached until she has.
	await page.getByRole('link', { name: 'Domains' }).click();
	await expect(page).toHaveURL('/account/two-factor');
	await expect(page.getByText('You need to set up two-factor login before you can use the app.')).toBeVisible();
	await expect(page.getByRole('link', { name: 'Domains' })).toHaveCount(0);
	await page.goto('/domains?target=i-1');
	await expect(page).toHaveURL('/account/two-factor');

	await setUp(page);
	await page.getByRole('button', { name: "I've saved them" }).click();
	await expect(page).toHaveURL('/dashboard?target=i-1');
	await expect(page.getByRole('link', { name: 'Domains' })).toBeVisible();

	// The users page shows it, and an admin who is sure it's her can remove it, which logs her out.
	await admin.goto('/admin/users');
	const umaRow = admin.getByRole('row').filter({ hasText: 'uma' });
	await expect(umaRow.getByRole('cell').nth(3)).toHaveText('On');
	await umaRow.getByRole('button', { name: 'Actions for uma' }).click();
	await admin.getByRole('menuitem', { name: 'Remove two-factor login' }).click();
	await admin.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
	await expect(admin.getByText("uma's two-factor login removed.")).toBeVisible();
	await expect(umaRow.getByRole('cell').nth(3)).toHaveText('Required, not set up');

	await page.reload();
	await expect(page).toHaveURL(/\/login/);
	// Her role still requires it, so the password alone takes her straight to setting it up again.
	await logIn(page, uma);
	await expect(page).toHaveURL('/account/two-factor');

	// Exempting her wins over her role: her next page is the app.
	await umaRow.getByRole('button', { name: 'Actions for uma' }).click();
	await admin.getByRole('menuitem', { name: 'Two-factor setting' }).click();
	const dialog = admin.getByRole('dialog');
	await dialog.getByRole('radio', { name: /Not required for this user/ }).check();
	await dialog.getByRole('button', { name: 'Save' }).click();
	await expect(umaRow).toContainText('Exempt');
	await expect(umaRow.getByRole('cell').nth(3)).toHaveText(/^Off\s*Exempt$/);
	await page.goto('/');
	await expect(page).toHaveURL('/dashboard?target=i-1');

	await apiWrite(admin, 'DELETE', `/api/v1/users/${await idOf(admin, 'users', 'uma')}`);
	await apiWrite(admin, 'DELETE', `/api/v1/roles/${roleID}`);
	await admin.context().close();
});
