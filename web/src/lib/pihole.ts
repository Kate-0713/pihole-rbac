// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// What the domains and clients pages share: Pi-hole's groups, and the server's rule for comments (checkText in
// internal/api/targets.go), copied here so a form can say what's wrong before it is sent. The server checks again.
import type { Schemas } from '#lib/api/client.js';

export type PiholeGroup = Schemas['PiholeGroup'];

export const maxCommentChars = 500;

// Control characters, line breaks included, as Go's unicode.IsControl sees them.
// eslint-disable-next-line no-control-regex
export const controlChars = /[\u0000-\u001f\u007f-\u009f]/;

// commentProblem returns what's wrong with a comment, or null.
export function commentProblem(comment: string): string | null {
	if ([...comment].length > maxCommentChars) return `A comment can be at most ${maxCommentChars} characters.`;
	if (controlChars.test(comment)) return "A comment can't contain control characters or line breaks.";
	return null;
}

// groupNames names a list of group IDs, in the order of the Pi-hole's own list, with #<id> for a group it no longer
// lists.
export function groupNames(ids: readonly number[], groups: readonly PiholeGroup[]): string[] {
	const known = groups.filter((g) => ids.includes(g.id)).map((g) => g.name);
	const missing = ids.filter((id) => !groups.some((g) => g.id === id)).map((id) => `#${id}`);
	return [...known, ...missing];
}
