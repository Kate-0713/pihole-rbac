// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineParams } from '@sveltejs/kit/params';

// SvelteKit 3's param matchers, all in one file. A route folder named [id=integer] only matches when the function
// returns a value, so /admin/roles/abc is the not-found page rather than a page that asks the API for role "abc".
// What the function returns becomes the param: params.id is a number, not a string. (SvelteKit 2 had one file per
// matcher in src/params/, returning a boolean.)
export const params = defineParams({
	integer: (param) => (/^[1-9][0-9]{0,15}$/.test(param) ? Number(param) : undefined)
});
