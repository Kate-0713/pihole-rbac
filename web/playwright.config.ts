// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// End-to-end tests: Playwright drives Chromium against the real binary (frontend embedded) and a fake Pi-hole, all
// started by the Go command internal/e2e/cmd/e2e-server. Build the binary first; make e2e and .\build.ps1 e2e do both.
import { defineConfig, devices } from '@playwright/test';
import { control, fresh, seeded, stateURL } from './e2e/addresses.js';

// The config runs in Node. These are the only two parts of `process` it uses, declared here rather than adding
// @types/node, whose globals would then also type-check in browser code where they don't exist.
declare const process: { env: Record<string, string | undefined>; platform: string };

// To use a Chromium that is already installed instead of the one `npx playwright install chromium` downloads.
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined;

export default defineConfig({
	testDir: 'e2e',
	// The servers are shared, and the setup test changes the fresh one for good, so tests run one at a time. The
	// suite is small; reliability matters more than speed here.
	workers: 1,
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: 0,
	reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
	use: {
		...devices['Desktop Chrome'],
		launchOptions: { executablePath },
		trace: 'retain-on-failure'
	},
	projects: [
		// First-run setup, against the server whose setup is still open. It completes setup, so it runs once.
		{ name: 'setup', testMatch: 'setup.spec.ts', use: { baseURL: `http://${fresh}` } },
		// Everything else, against the seeded server.
		{ name: 'app', testIgnore: 'setup.spec.ts', use: { baseURL: `http://${seeded}` } }
	],
	webServer: {
		command: `go run ../internal/e2e/cmd/e2e-server -binary ../bin/pihole-rbac${process.platform === 'win32' ? '.exe' : ''} -control ${control} -fresh ${fresh} -seeded ${seeded}`,
		url: stateURL,
		// Never reuse a running one: the setup test needs a server whose setup is still open.
		reuseExistingServer: false,
		// go run compiles first, which can take a while on a cold cache.
		timeout: 180_000,
		stdout: 'pipe',
		stderr: 'pipe',
		// SIGINT lets the e2e server stop both binaries and remove its data directories.
		gracefulShutdown: { signal: 'SIGINT', timeout: 10_000 }
	}
});
