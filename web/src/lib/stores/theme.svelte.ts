// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Light or dark mode: the user's choice (light, dark, or system to follow the operating system), kept in this browser
// only. The dark colours are the `.dark` variables in app.css; this store decides when <html> has that class.
//
// app.html has a small inline script that applies the same choice before the page is drawn, so a dark page doesn't
// flash white while the app loads. It reads the same storage key: keep the two in step (a test checks).

export type ThemeChoice = 'light' | 'dark' | 'system';
export type Theme = 'light' | 'dark';

export const themeStorageKey = 'pihole-rbac-theme';
const darkQuery = '(prefers-color-scheme: dark)';

export function parseChoice(v: unknown): ThemeChoice {
	return v === 'light' || v === 'dark' ? v : 'system';
}

export function resolveTheme(choice: ThemeChoice, systemDark: boolean): Theme {
	if (choice === 'system') return systemDark ? 'dark' : 'light';
	return choice;
}

// The parts of the browser the store uses, so tests can pass their own.
export type ThemeEnv = {
	storage?: Pick<Storage, 'getItem' | 'setItem'>;
	media?: (query: string) => Pick<MediaQueryList, 'matches' | 'addEventListener' | 'removeEventListener'>;
};

function browserEnv(): ThemeEnv {
	const env: ThemeEnv = {};
	try {
		if (typeof localStorage !== 'undefined') env.storage = localStorage;
	} catch {
		// Storage blocked (site data off): the choice lasts until the page is reloaded.
	}
	if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') env.media = (q) => window.matchMedia(q);
	return env;
}

export class ThemeStore {
	choice = $state<ThemeChoice>('system');
	systemDark = $state(false);
	// $derived recomputes whenever choice or systemDark changes.
	resolved = $derived<Theme>(resolveTheme(this.choice, this.systemDark));

	#env: ThemeEnv;

	constructor(env: ThemeEnv = browserEnv()) {
		this.#env = env;
		try {
			this.choice = parseChoice(env.storage?.getItem(themeStorageKey));
		} catch {
			this.choice = 'system';
		}
	}

	// start follows the operating system's setting while the choice is "system", and returns a function that stops.
	// Meant to be returned from a $effect in the root layout.
	start(): () => void {
		const mq = this.#env.media?.(darkQuery);
		if (!mq) return () => {};
		this.systemDark = mq.matches;
		const changed = (e: MediaQueryListEvent) => {
			this.systemDark = e.matches;
		};
		mq.addEventListener('change', changed);
		return () => mq.removeEventListener('change', changed);
	}

	set(choice: ThemeChoice): void {
		this.choice = choice;
		try {
			this.#env.storage?.setItem(themeStorageKey, choice);
		} catch {
			// Not kept past this page load.
		}
	}
}

export const theme = new ThemeStore();

// applyTheme puts the resolved theme on <html>: the `dark` class the CSS keys on, and color-scheme, so the browser's
// own parts (scrollbars, form controls) match.
export function applyTheme(t: Theme, root: HTMLElement = document.documentElement): void {
	root.classList.toggle('dark', t === 'dark');
	root.style.colorScheme = t;
}
