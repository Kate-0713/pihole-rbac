// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [
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
	}
});
