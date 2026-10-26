// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
// ?raw is Vite's way to import a file's text: the page template, to check its inline script against the store.
import appHtml from '../../app.html?raw';
import { ThemeStore, parseChoice, resolveTheme, themeStorageKey, type ThemeEnv } from './theme.svelte.js';

function memoryStorage(initial: Record<string, string> = {}, throws = false) {
	const m = new Map(Object.entries(initial));
	const check = () => {
		if (throws) throw new DOMException('blocked', 'SecurityError');
	};
	return {
		map: m,
		getItem: (k: string) => (check(), m.get(k) ?? null),
		setItem: (k: string, v: string) => (check(), void m.set(k, v))
	};
}

// A media query whose answer the test changes, as the operating system would.
function fakeMedia(dark: boolean) {
	const listeners = new Set<(e: MediaQueryListEvent) => void>();
	const mq = {
		matches: dark,
		addEventListener: (_: string, l: (e: MediaQueryListEvent) => void) => listeners.add(l),
		removeEventListener: (_: string, l: (e: MediaQueryListEvent) => void) => listeners.delete(l),
		flip(to: boolean) {
			mq.matches = to;
			for (const l of listeners) l({ matches: to } as MediaQueryListEvent);
		},
		listeners
	};
	return mq;
}

describe('theme rules', () => {
	it('reads a stored choice, defaulting to system', () => {
		expect(parseChoice('dark')).toBe('dark');
		expect(parseChoice('light')).toBe('light');
		for (const v of ['system', null, undefined, '', 'Dark', '"dark"']) expect(parseChoice(v)).toBe('system');
	});
	it('follows the system only when asked to', () => {
		expect(resolveTheme('system', true)).toBe('dark');
		expect(resolveTheme('system', false)).toBe('light');
		expect(resolveTheme('light', true)).toBe('light');
		expect(resolveTheme('dark', false)).toBe('dark');
	});
});

describe('ThemeStore', () => {
	it('keeps the choice in this browser', () => {
		const storage = memoryStorage();
		const a = new ThemeStore({ storage });
		expect(a.choice).toBe('system');
		a.set('dark');
		expect(a.resolved).toBe('dark');
		expect(storage.map.get(themeStorageKey)).toBe('dark');
		expect(new ThemeStore({ storage }).choice).toBe('dark');
	});

	it('follows the operating system while the choice is system', () => {
		const media = fakeMedia(false);
		const s = new ThemeStore({ storage: memoryStorage(), media: () => media } as ThemeEnv);
		const stop = s.start();
		expect(s.resolved).toBe('light');
		media.flip(true);
		expect(s.resolved).toBe('dark');
		s.set('light');
		expect(s.resolved).toBe('light'); // an explicit choice wins
		stop();
		expect(media.listeners.size).toBe(0);
	});

	it('still works when storage is blocked', () => {
		const s = new ThemeStore({ storage: memoryStorage({}, true) });
		expect(s.choice).toBe('system');
		s.set('dark');
		expect(s.resolved).toBe('dark');
	});
});

describe('app.html', () => {
	it("applies the stored choice before the app loads, with the store's key", () => {
		const script = /<script>([\s\S]*?)<\/script>/.exec(appHtml)?.[1] ?? '';
		expect(script).toContain(`'${themeStorageKey}'`);
		expect(script).toContain('prefers-color-scheme: dark');
		expect(script).toContain('try');
	});
});
