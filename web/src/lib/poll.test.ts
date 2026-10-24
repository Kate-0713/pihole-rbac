// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { whileVisible, type VisibilitySource } from './poll.js';

// A document whose visibility the test controls.
class FakeDocument implements VisibilitySource {
	hidden = false;
	listeners = new Set<() => void>();
	addEventListener(_: 'visibilitychange', l: () => void) {
		this.listeners.add(l);
	}
	removeEventListener(_: 'visibilitychange', l: () => void) {
		this.listeners.delete(l);
	}
	setHidden(hidden: boolean) {
		this.hidden = hidden;
		for (const l of this.listeners) l();
	}
}

describe('whileVisible', () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it('calls fn every interval while visible, starting after the first interval', () => {
		const doc = new FakeDocument();
		const fn = vi.fn();
		whileVisible(fn, 1000, doc);
		expect(fn).not.toHaveBeenCalled();
		vi.advanceTimersByTime(3000);
		expect(fn).toHaveBeenCalledTimes(3);
	});

	it('stops while hidden, and calls fn at once when shown again', () => {
		const doc = new FakeDocument();
		const fn = vi.fn();
		whileVisible(fn, 1000, doc);
		doc.setHidden(true);
		vi.advanceTimersByTime(5000);
		expect(fn).not.toHaveBeenCalled();

		doc.setHidden(false);
		expect(fn).toHaveBeenCalledTimes(1);
		vi.advanceTimersByTime(1000);
		expect(fn).toHaveBeenCalledTimes(2);
	});

	it("doesn't start when the page is hidden to begin with", () => {
		const doc = new FakeDocument();
		doc.hidden = true;
		const fn = vi.fn();
		whileVisible(fn, 1000, doc);
		vi.advanceTimersByTime(5000);
		expect(fn).not.toHaveBeenCalled();
	});

	it('stops for good when the returned function is called', () => {
		const doc = new FakeDocument();
		const fn = vi.fn();
		const stop = whileVisible(fn, 1000, doc);
		stop();
		vi.advanceTimersByTime(5000);
		doc.setHidden(true);
		doc.setHidden(false);
		expect(fn).not.toHaveBeenCalled();
		expect(doc.listeners.size).toBe(0);
	});
});
