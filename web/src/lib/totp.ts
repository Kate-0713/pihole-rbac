// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Two-factor login (TOTP): the parts of it the pages share.
import { ApiError } from '#lib/api/client.js';

// Whether a refusal at the code step of a login means starting again from the password. A wrong code (totp_invalid)
// or a rate limit leaves the login waiting, so the code form stays. Anything else ends it: it ran out of time or
// attempts (login_expired), the account can no longer log in (invalid_credentials) or has no role (no_access). An
// error that isn't the server's (the network, say) says nothing about the login, so the code form stays for another
// try.
export function restartsLogin(e: unknown): boolean {
	if (!(e instanceof ApiError)) return false;
	return e.code === 'login_expired' || e.code === 'invalid_credentials' || e.code === 'no_access';
}
