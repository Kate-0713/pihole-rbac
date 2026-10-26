// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

/// <reference types="vitest/config" />
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import license from 'rollup-plugin-license';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

// Licences the bundled npm packages may have. Anything else, or a package with no licence, fails the build: the
// notices ship with every release (see deploy/notices/notices.sh, which adds the Go modules).
const allowedLicences = new Set([
	'MIT',
	'ISC',
	'0BSD',
	'BSD-2-Clause',
	'BSD-3-Clause',
	'Apache-2.0',
	'MPL-2.0',
	'CC0-1.0',
	'OFL-1.1',
	'Unlicense'
]);
// Packages whose package.json has no "license" field, with the licence their LICENSE file holds (checked by hand;
// recheck when they are updated).
const licenceOverrides: Record<string, string> = {
	runed: 'MIT',
	'svelte-toolbelt': 'MIT'
};

const licenceOf = (d: { name: string | null; license: string | null }) =>
	d.license ?? (d.name ? licenceOverrides[d.name] : undefined);

// licenceAllowed accepts a single licence or a simple SPDX expression: "A OR B" needs one allowed, "A AND B" all.
function licenceAllowed(expr: string | undefined): boolean {
	if (!expr) return false;
	const e = expr.replace(/[()]/g, ' ').trim();
	if (/ AND /i.test(e) && / OR /i.test(e)) return false; // mixed expressions are checked by hand
	if (/ AND /i.test(e)) return e.split(/ AND /i).every((l) => allowedLicences.has(l.trim()));
	return e.split(/ OR /i).some((l) => allowedLicences.has(l.trim()));
}

// Packages that reach the bundle through CSS (the font files, Tailwind's generated base styles, the animations),
// which the plugin can't see because it follows JavaScript modules only.
const cssPackages = ['@fontsource-variable/inter', 'tailwindcss', 'tw-animate-css'];

type Notice = {
	name: string | null;
	version: string | null;
	license: string | null;
	licenseText: string | null;
	repository?: string | { url: string } | null;
};

function readPackage(name: string): Notice {
	const dir = fileURLToPath(new URL(`./node_modules/${name}/`, import.meta.url));
	const pkg = JSON.parse(readFileSync(dir + 'package.json', 'utf8'));
	const file = readdirSync(dir).find((f) => /^(licen[cs]e|copying)/i.test(f));
	const notice: Notice = {
		name: pkg.name,
		version: pkg.version,
		license: pkg.license ?? null,
		licenseText: file ? readFileSync(dir + file, 'utf8') : null,
		repository: pkg.repository ?? null
	};
	if (!licenceAllowed(licenceOf(notice)) || !notice.licenseText) {
		throw new Error(
			`${name}: licence ${notice.license ?? 'missing'} isn't allowed, or it has no licence file`
		);
	}
	return notice;
}

// The client build's third-party packages, with their licence texts, written to build/notices-web.txt (outside
// build/app, which the adapter empties on each build). The SSR build is skipped: SSR is off and nothing from it ships.
function webNotices(): Plugin {
	return {
		...(license({
			thirdParty: {
				includePrivate: false,
				allow: {
					test: (d) => licenceAllowed(licenceOf(d)),
					failOnUnlicensed: true,
					failOnViolation: true
				},
				output: {
					file: fileURLToPath(new URL('./build/notices-web.txt', import.meta.url)),
					template: (deps) =>
						[...deps, ...cssPackages.map(readPackage)]
							.toSorted((a, b) => (a.name ?? '').localeCompare(b.name ?? ''))
							.map(
								(d) =>
									`${d.name}@${d.version}\nLicense: ${licenceOf(d)}\n` +
									(d.repository
										? `Source: ${typeof d.repository === 'string' ? d.repository : d.repository.url}\n`
										: '') +
									`\n${(d.licenseText ?? '').trim()}\n`
							)
							.join('\n' + '-'.repeat(80) + '\n\n')
				}
			}
		}) as Plugin),
		name: 'pihole-rbac-web-notices',
		apply: (_config, env) => env.command === 'build' && !env.isSsrBuild
	};
}

export default defineConfig({
	plugins: [
		webNotices(),
		// Tailwind CSS v4's Vite plugin; it goes before sveltekit() so it sees the CSS first.
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// Static SPA: nothing is prerendered, every route is served by the
			// fallback page, and the Go binary embeds the output.
			// Output goes to build/app (not build/) because the adapter deletes its
			// output directory on every build, and build/.keep must survive so the
			// Go embed compiles before the frontend has been built.
			adapter: adapter({
				pages: 'build/app',
				assets: 'build/app',
				fallback: 'index.html',
				precompress: false,
				strict: true
			})
		})
	],
	server: {
		// The Go API runs on :8080 in development. Proxying /api keeps the
		// browser on a single origin, so cookies and the Origin check behave
		// as they do in production.
		proxy: {
			'/api': {
				target: 'http://localhost:8080',
				changeOrigin: false
			}
		}
	},
	// Vitest reads this same config, so tests compile .svelte.ts modules and resolve #lib and $app as the app does.
	// Unit tests sit next to the code as *.test.ts; the Playwright tests in e2e/ are run by Playwright, not Vitest.
	test: {
		include: ['src/**/*.test.ts'],
		environment: 'node'
	}
});
