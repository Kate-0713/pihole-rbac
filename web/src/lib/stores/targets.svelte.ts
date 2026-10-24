// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The targets (instances, and later mirrored groups) the user can act on, and which one is selected. The selection
// lives in the URL as ?target=i-1, so links can be shared; the last one picked is also remembered in this browser, so
// a link without it opens where the user left off.
import { api, unwrap, type Schemas } from '#lib/api/client.js';

export type Target = Schemas['Target'];

const rememberKey = 'pihole-rbac.target';

class TargetsStore {
	list = $state<Target[]>([]);
	loaded = $state(false);

	#loading: Promise<void> | null = null;

	// Loads the list once; refresh() asks again (the health shown beside each target changes over time).
	load(fetch: typeof globalThis.fetch = globalThis.fetch): Promise<void> {
		this.#loading ??= this.#fetch(fetch).catch((e: unknown) => {
			this.#loading = null;
			throw e;
		});
		return this.#loading;
	}

	async refresh(): Promise<void> {
		await this.#fetch(globalThis.fetch);
	}

	async #fetch(fetch: typeof globalThis.fetch): Promise<void> {
		const { targets } = await unwrap(api.GET('/api/v1/targets', { fetch }));
		this.list = targets;
		this.loaded = true;
	}

	// Forgets everything, for logout: the next user may see other instances.
	reset(): void {
		this.list = [];
		this.loaded = false;
		this.#loading = null;
	}

	find(id: string | null | undefined): Target | undefined {
		return id ? this.list.find((t) => t.id === id) : undefined;
	}

	// The target to show when the URL doesn't name a usable one: the one picked last in this browser, else the first.
	fallback(): Target | undefined {
		return this.find(readRemembered()) ?? this.list[0];
	}

	remember(id: string): void {
		try {
			localStorage.setItem(rememberKey, id);
		} catch {
			// Storage can be unavailable (private windows, blocked site data); remembering is only a convenience.
		}
	}
}

function readRemembered(): string | null {
	try {
		return localStorage.getItem(rememberKey);
	} catch {
		return null;
	}
}

export const targets = new TargetsStore();

// usesTarget says whether a page acts on the selected target. Admin pages don't, and their URLs never carry one.
export function usesTarget(pathname: string): boolean {
	return pathname !== '/admin' && !pathname.startsWith('/admin/');
}

// withTarget adds the selected target to an in-app link, so moving between pages keeps it. Links to admin pages are
// left as they are.
export function withTarget(path: string, target: string | null | undefined): string {
	const url = new URL(path, 'http://x');
	if (!target || !usesTarget(url.pathname)) return path;
	url.searchParams.set('target', target);
	return url.pathname + url.search;
}
