// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { DriftReport } from '#lib/drift.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_driftKey) reads the report again: after Check now, and while the page is on screen.
export const _driftKey = 'app:drift';

type Data = {
	report: DriftReport | null;
	// The group's ID, when the target is a mirrored group.
	groupId: number | null;
	error: string | null;
	allowed: boolean;
};

export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_driftKey);
	const { target } = await parent();
	// Only a mirrored group has drift: its target is g-<id>.
	const groupId = target?.startsWith('g-') ? Number(target.slice(2)) : null;
	if (!target || groupId === null) return { report: null, groupId: null, error: null, allowed: true };
	if (!can('drift.view', target)) return { report: null, groupId, error: null, allowed: false };
	try {
		const report = await unwrap(api.GET('/api/v1/instance-groups/{id}/drift', { params: { path: { id: groupId } }, fetch }));
		return { report, groupId, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { report: null, groupId, error: e.message, allowed: true };
		throw e;
	}
};
