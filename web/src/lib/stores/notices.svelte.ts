// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// How the app tells the user what happened, as in v1: a success is a toast that fades on its own, a failure stays on
// screen until it is dismissed, so it can't be missed.
import { toast } from 'svelte-sonner';
import { ApiError } from '#lib/api/client.js';

export type Notice = { id: number; message: string };

// Keep the newest few; an error that repeats doesn't need ten copies.
const maxErrors = 5;

class NoticesStore {
	errors = $state<Notice[]>([]);
	#next = 1;

	success(message: string): void {
		toast.success(message);
	}

	info(message: string): void {
		toast.info(message);
	}

	// error takes a message or whatever a failed call threw. An ApiError's message comes from the server and is
	// written to be shown; anything else gets a generic message, with the details only in the console.
	error(e: unknown, context?: string): void {
		let message: string;
		if (e instanceof ApiError) {
			message = e.message;
		} else if (typeof e === 'string') {
			message = e;
		} else {
			console.error(e);
			message = 'Something went wrong.';
		}
		const notice: Notice = { id: this.#next++, message: context ? `${context}: ${message}` : message };
		this.errors = [notice, ...this.errors.filter((n) => n.message !== notice.message)].slice(0, maxErrors);
	}

	dismiss(id: number): void {
		this.errors = this.errors.filter((n) => n.id !== id);
	}

	clear(): void {
		this.errors = [];
	}
}

export const notices = new NoticesStore();
