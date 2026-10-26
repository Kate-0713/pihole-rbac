// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The update status, shared by the update banner (on every page) and the System page, so the banner follows what
// the System page last read without asking the server again on every navigation.
import { api, unwrap } from '#lib/api/client.js';
import type { UpdateStatus } from '#lib/system.js';

// Which release the banner was dismissed for. Per browser, and only a convenience: if storage isn't available
// (a private window, say), the banner simply comes back on the next visit.
const dismissedKey = 'pihole-rbac:update-banner-dismissed';

function readDismissed(storage: Storage | undefined): string | null {
	try {
		return storage?.getItem(dismissedKey) ?? null;
	} catch {
		return null;
	}
}

function browserStorage(): Storage | undefined {
	try {
		return typeof localStorage === 'undefined' ? undefined : localStorage;
	} catch {
		return undefined;
	}
}

export class UpdatesStore {
	status = $state<UpdateStatus | null>(null);
	dismissed = $state<string | null>(null);

	#storage: Storage | undefined;
	#read: () => Promise<UpdateStatus>;
	// The user whose status this is. It is read once per login; the System page refreshes it.
	#loadedFor: number | null = null;

	// Tests pass their own storage and reader.
	constructor(
		storage: Storage | undefined = browserStorage(),
		read: () => Promise<UpdateStatus> = () => unwrap(api.GET('/api/v1/system/update'))
	) {
		this.#storage = storage;
		this.#read = read;
		this.dismissed = readDismissed(storage);
	}

	// ensure reads the status once for this user. A failure leaves no banner: the System page shows the error.
	async ensure(userId: number): Promise<void> {
		if (this.#loadedFor === userId) return;
		this.#loadedFor = userId;
		try {
			this.status = await this.#read();
		} catch {
			this.status = null;
		}
	}

	// set records a status the System page read, so the banner agrees with it.
	set(status: UpdateStatus | null): void {
		this.status = status;
	}

	dismiss(version: string): void {
		this.dismissed = version;
		try {
			this.#storage?.setItem(dismissedKey, version);
		} catch {
			// Not kept past this page load; nothing else to do.
		}
	}

	// reset forgets the status when the session ends, so the next user's is read afresh.
	reset(): void {
		this.status = null;
		this.#loadedFor = null;
	}
}

export const updates = new UpdatesStore();
