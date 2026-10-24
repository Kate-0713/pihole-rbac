// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Browser-side copies of the server's rules for usernames and passwords, so forms can say what's wrong before
// submitting. They are a convenience only: the server checks the same rules and its answer wins.

const usernamePattern = /^[a-z0-9][a-z0-9._-]{0,63}$/;

// usernameProblem returns what's wrong with a new local username, or null. Uppercase is fine: the server folds it.
export function usernameProblem(username: string): string | null {
	const u = username.trim().toLowerCase();
	if (u === '') return null; // nothing typed yet: not an error to show
	if (!usernamePattern.test(u)) {
		return "Use 1–64 letters, digits, '.', '_' or '-', starting with a letter or digit.";
	}
	return null;
}

// passwordProblem returns what's wrong with a new password and its confirmation, or null. Every form that sets a
// password asks for it twice.
export function passwordProblem(password: string, confirm: string): string | null {
	if (password === '') return null;
	// Characters as the server counts them (code points), not UTF-16 units.
	if ([...password].length < 12) return 'Use at least 12 characters.';
	// bcrypt only uses the first 72 bytes, so the server refuses anything longer.
	if (new TextEncoder().encode(password).length > 72) return 'Use at most 72 bytes (fewer if it has non-ASCII characters).';
	if (confirm !== '' && confirm !== password) return "The passwords don't match.";
	return null;
}

// passwordReady says whether the form may be submitted.
export function passwordReady(password: string, confirm: string): boolean {
	return password !== '' && password === confirm && passwordProblem(password, confirm) === null;
}
