// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared Playwright fixtures. Import `test` and `expect` from here, not from @playwright/test, so every test gets
// the CSP and page-error checks and can read the e2e server's state.
import { test as base, expect, type Page } from '@playwright/test';
import { stateURL } from './addresses.js';

// What internal/e2e/cmd/e2e-server reports on GET /state.
export type User = { username: string; password: string; about: string };
export type Instance = { id: number; name: string; env_name: string; base_url: string };
export type State = {
	fresh: { url: string; setup_token: string };
	seeded: {
		url: string;
		fixture: { admin: User; one_instance: User; no_instances: User; instances: Instance[] };
	};
};

type Fixtures = { state: State; problems: string[] };

export const test = base.extend<Fixtures>({
	// Read once per test; it's a local request.
	state: async ({ request }, use) => {
		const res = await request.get(stateURL);
		expect(res.ok()).toBe(true);
		await use((await res.json()) as State);
	},

	// Collected for every test, and checked after it: a CSP violation or an uncaught error fails the test even if
	// everything it looked at was right. `auto: true` makes Playwright set it up without the test asking for it.
	problems: [
		async ({ page }, use) => {
			const problems: string[] = [];
			page.on('console', (msg) => {
				const text = msg.text();
				if (msg.type() === 'error' && /Content Security Policy|Refused to (load|execute|apply)/i.test(text)) {
					problems.push(`CSP: ${text}`);
				}
			});
			page.on('pageerror', (err) => problems.push(`page error: ${err.message}`));
			await use(problems);
			expect(problems, 'CSP violations or page errors').toEqual([]);
		},
		{ auto: true }
	]
});

export { expect };

// logIn fills in the login form, which the page must already show, and submits it.
export async function logIn(page: Page, user: User): Promise<void> {
	await page.getByLabel('Username').fill(user.username);
	await page.getByLabel('Password').fill(user.password);
	await page.getByRole('button', { name: 'Log in' }).click();
}

// openAs opens path as user, logging in on the way.
export async function openAs(page: Page, user: User, path = '/'): Promise<void> {
	await page.goto(path);
	await expect(page).toHaveURL(/\/login/);
	await logIn(page, user);
	await expect(page).not.toHaveURL(/\/login/);
}

// The target picker in the header (bits-ui's Select), labelled "Instance".
export function picker(page: Page) {
	return page.getByRole('combobox', { name: 'Instance' });
}
