// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The session store: who is logged in, their permissions and the CSRF token. It is the only place the SPA decides
// whether someone is logged in; the server still checks every request.
//
// Svelte convention: runes ($state, $derived) only work in .svelte files and in modules named *.svelte.ts or
// *.svelte.js, which is why this file has that name. A class with $state fields is the Svelte 5 replacement for
// writable() stores: components read `session.user` directly and re-render when it changes, with no $ prefix and no
// subscribe().
import { goto } from '$app/navigation';
import { ApiError, api, onSessionResponses, setCSRFToken, unwrap, type Schemas } from '#lib/api/client.js';

export type CurrentSession = Schemas['CurrentSession'];
export type SessionUser = Schemas['SessionUser'];

// unknown: not asked yet. setup: first-run setup isn't done. anonymous: no session. authenticated: logged in.
export type SessionStatus = 'unknown' | 'setup' | 'anonymous' | 'authenticated';

class SessionStore {
	status = $state<SessionStatus>('unknown');
	current = $state<CurrentSession | null>(null);

	// $derived recomputes when the $state it reads changes, like a computed property.
	user = $derived<SessionUser | null>(this.current?.user ?? null);

	#init: Promise<void> | null = null;

	// Asks the server once, however often it is called: the root layout's load awaits it before any page renders.
	// Takes SvelteKit's fetch, as load functions should.
	init(fetch: typeof globalThis.fetch): Promise<void> {
		this.#init ??= this.#load(fetch).catch((e: unknown) => {
			this.#init = null; // let a reload try again
			throw e;
		});
		return this.#init;
	}

	async #load(fetch: typeof globalThis.fetch): Promise<void> {
		try {
			this.#set(await unwrap(api.GET('/api/v1/auth/session', { fetch })));
		} catch (e) {
			if (e instanceof ApiError && e.code === 'unauthenticated') return this.#clear('anonymous');
			if (e instanceof ApiError && e.code === 'setup_required') return this.#clear('setup');
			throw e;
		}
	}

	// Login and setup are state-changing requests made before there is a session, so they need the anonymous CSRF
	// token first. Fetched fresh each time: an anonymous token stops working once there is a session.
	async #anonymousCSRF(): Promise<void> {
		const { csrf_token } = await unwrap(api.GET('/api/v1/auth/csrf'));
		setCSRFToken(csrf_token);
	}

	async login(username: string, password: string): Promise<void> {
		await this.#anonymousCSRF();
		this.#set(await unwrap(api.POST('/api/v1/auth/login', { body: { username, password } })));
	}

	async completeSetup(token: string, username: string, password: string): Promise<void> {
		await this.#anonymousCSRF();
		this.#set(await unwrap(api.POST('/api/v1/setup', { body: { token, username, password } })));
	}

	// Ends the session on the server. A session that has already gone (401) counts as logged out; any other failure
	// is thrown, so the caller can say the logout didn't happen rather than pretend it did.
	async logout(): Promise<void> {
		try {
			await unwrap(api.POST('/api/v1/auth/logout'));
		} catch (e) {
			if (!(e instanceof ApiError && e.code === 'unauthenticated')) throw e;
		}
		this.#clear('anonymous');
	}

	#set(s: CurrentSession): void {
		this.current = s;
		this.status = 'authenticated';
		setCSRFToken(s.csrf_token);
	}

	#clear(status: Exclude<SessionStatus, 'authenticated'>): void {
		this.current = null;
		this.status = status;
		setCSRFToken(null);
	}

	// Called by the API client when any request finds the session gone or setup not done.
	expired(): void {
		if (this.status !== 'authenticated') return;
		this.#clear('anonymous');
		void goto(loginURL(currentPath()));
	}

	setupRequired(): void {
		// While init is still asking, #load handles the answer itself.
		if (this.status === 'unknown' || this.status === 'setup') return;
		this.#clear('setup');
		void goto('/setup');
	}
}

export const session = new SessionStore();

onSessionResponses({
	unauthenticated: () => session.expired(),
	setupRequired: () => session.setupRequired()
});

function currentPath(): string {
	return window.location.pathname + window.location.search;
}

// The login page sends the user back to `next` afterwards.
export function loginURL(next: string): string {
	return next === '/' ? '/login' : `/login?next=${encodeURIComponent(next)}`;
}

// safeNext only accepts a path on this site, so a crafted link (/login?next=https://evil.example, or //evil.example)
// can't send someone elsewhere after they log in.
export function safeNext(next: string | null): string {
	if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/';
	if (next === '/login' || next.startsWith('/login?') || next.startsWith('/setup')) return '/';
	return next;
}
