// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// The update status, shared by the update banner (on every page) and the System page, so the banner follows what
// the System page last read without asking the server again on every navigation. People with app.update get the
// full status; everyone else gets only what the version endpoint says about the latest release.
import { api, unwrap } from '#lib/api/client.js';
import {
	bannerFromStatus,
	bannerFromVersion,
	type BannerInfo,
	type UpdateStatus,
	type VersionInfo
} from '#lib/system.js';

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
	// The full status, only for app.update holders.
	status = $state<UpdateStatus | null>(null);
	// What the banner shows, for everyone.
	banner = $state<BannerInfo | null>(null);
	dismissed = $state<string | null>(null);

	#storage: Storage | undefined;
	#readStatus: () => Promise<UpdateStatus>;
	#readVersion: () => Promise<VersionInfo>;
	// Whose status this is, and whether it was the full one. It is read once per login; the System page refreshes it.
	#loadedFor: string | null = null;

	// Tests pass their own storage and readers.
	constructor(
		storage: Storage | undefined = browserStorage(),
		readStatus: () => Promise<UpdateStatus> = () => unwrap(api.GET('/api/v1/system/update')),
		readVersion: () => Promise<VersionInfo> = () => unwrap(api.GET('/api/v1/system/version'))
	) {
		this.#storage = storage;
		this.#readStatus = readStatus;
		this.#readVersion = readVersion;
		this.dismissed = readDismissed(storage);
	}

	// ensure reads what the banner needs once for this user: the full status when they can update, the version
	// endpoint otherwise. A failure leaves no banner: the System page shows the error.
	async ensure(userId: number, canUpdate: boolean): Promise<void> {
		const key = `${userId}:${canUpdate}`;
		if (this.#loadedFor === key) return;
		this.#loadedFor = key;
		try {
			if (canUpdate) {
				this.set(await this.#readStatus());
			} else {
				this.status = null;
				this.banner = bannerFromVersion(await this.#readVersion());
			}
		} catch {
			this.status = null;
			this.banner = null;
		}
	}

	// set records a status the System page read, so the banner agrees with it.
	set(status: UpdateStatus | null): void {
		this.status = status;
		this.banner = status ? bannerFromStatus(status) : null;
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
		this.banner = null;
		this.#loadedFor = null;
	}
}

export const updates = new UpdatesStore();
