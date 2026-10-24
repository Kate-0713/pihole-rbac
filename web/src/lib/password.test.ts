// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// These mirror the server's rules in internal/auth: if one side changes, the other should too.
import { describe, expect, it } from 'vitest';
import { passwordProblem, passwordReady, usernameProblem } from './password.js';

describe('usernameProblem', () => {
	it.each([
		['', null], // nothing typed yet
		['admin', null],
		['Admin', null], // the server folds case
		['  admin  ', null], // and trims
		['a.b_c-d9', null],
		['a'.repeat(64), null],
		['a'.repeat(65), 'too long'],
		['.admin', 'leading dot'],
		['-admin', 'leading dash'],
		['ad min', 'space'],
		['ädmin', 'non-ASCII']
	])('%j', (name, want) => {
		const problem = usernameProblem(name);
		if (want === null) expect(problem).toBeNull();
		else expect(problem, want).not.toBeNull();
	});
});

describe('passwordProblem', () => {
	const ok = 'correct horse battery';

	it('says nothing before anything is typed', () => {
		expect(passwordProblem('', '')).toBeNull();
	});

	it('needs at least 12 characters, counted as code points', () => {
		expect(passwordProblem('a'.repeat(11), '')).toMatch(/12 characters/);
		expect(passwordProblem('a'.repeat(12), '')).toBeNull();
		// 11 emoji are 22 UTF-16 units but only 11 characters.
		expect(passwordProblem('😀'.repeat(11), '')).toMatch(/12 characters/);
	});

	it('refuses more than 72 bytes, as bcrypt would ignore the rest', () => {
		expect(passwordProblem('a'.repeat(72), '')).toBeNull();
		expect(passwordProblem('a'.repeat(73), '')).toMatch(/72 bytes/);
		// 25 three-byte characters are 75 bytes.
		expect(passwordProblem('€'.repeat(25), '')).toMatch(/72 bytes/);
	});

	it('only complains about the confirmation once one is typed', () => {
		expect(passwordProblem(ok, '')).toBeNull();
		expect(passwordProblem(ok, 'something else')).toMatch(/match/);
		expect(passwordProblem(ok, ok)).toBeNull();
	});
});

describe('passwordReady', () => {
	it('needs a valid password typed twice', () => {
		expect(passwordReady('', '')).toBe(false);
		expect(passwordReady('short', 'short')).toBe(false);
		expect(passwordReady('correct horse battery', '')).toBe(false);
		expect(passwordReady('correct horse battery', 'correct horse batterY')).toBe(false);
		expect(passwordReady('correct horse battery', 'correct horse battery')).toBe(true);
	});
});
